let util = require('util');
const formidable = require('formidable');
const path = require('path');
const fs = require('fs-extra');
const docusign = require('docusign-esign');
const validator = require('validator');
const dsConfig = require('./config/index.js').config;
const eg001EmbeddedSigning = exports;
const eg = 'eg001';
const mustAuthenticate = '/ds/mustAuthenticate';
const minimumBufferMin = 3;
const signerClientId = 1000;
const dsReturnUrl = dsConfig.appUrl + '/ds-return';
const dsPingUrl = dsConfig.appUrl + '/';

eg001EmbeddedSigning.createController = async (req, res) => {
    let tokenOK = req.dsAuth.checkToken(minimumBufferMin);
    if (! tokenOK) {
        req.flash('info', 'Desculpe, você precisa se relogar.');        
        req.dsAuth.setEg(req, eg);
        res.redirect(mustAuthenticate);
    }    
    let body = req.body;
    let signerEmail = validator.escape(body.signerEmail);
    let signerName = validator.escape(body.signerName);
    let arquivo = (req.body.myfile);
    let envelopeArgs = {
            signerEmail: signerEmail,
            signerName: signerName,
            signerClientId: signerClientId,
            dsReturnUrl: dsReturnUrl,
            dsPingUrl: dsPingUrl,
            pdf1File: arquivo,
            demoDocsPath: path.resolve(__dirname, 'demo_documents')           
        }
    let args = {accessToken: req.user.accessToken, basePath: req.session.basePath, accountId: req.session.accountId, envelopeArgs: envelopeArgs};
    let results = null;    
    try {
        results = await eg001EmbeddedSigning.worker (args)
    }
    catch (error) {
        let errorBody = error && error.response && error.response.body;
        let errorCode = errorBody && errorBody.errorCode;
        let errorMessage = errorBody && errorBody.message;        
        res.render('pages/error', {err: error, errorCode: errorCode, errorMessage: errorMessage});
    }
    if (results) {        
        res.redirect(results.redirectUrl);
    }
}

eg001EmbeddedSigning.worker = async (args) => {    
    let dsApiClient = new docusign.ApiClient();
    dsApiClient.setBasePath(args.basePath);
    dsApiClient.addDefaultHeader('Authorization', 'Bearer ' + args.accessToken);
    let envelopesApi = new docusign.EnvelopesApi(dsApiClient)
    let results = null;
    let envelope = makeEnvelope(args.envelopeArgs)
    results = await envelopesApi.createEnvelope(args.accountId, {envelopeDefinition: envelope});
    let envelopeId = results.envelopeId;
    console.log(`Envelope criado, Id: ${envelopeId}`);    
    let viewRequest = makeRecipientViewRequest(args.envelopeArgs);    
    results = await envelopesApi.createRecipientView(args.accountId, envelopeId,
        {recipientViewRequest: viewRequest});
    return ({envelopeId: envelopeId, redirectUrl: results.url})
}

function makeEnvelope(args){
    let docPdfBytes;    
    docPdfBytes = fs.readFileSync(path.resolve(args.demoDocsPath, args.pdf1File));
    let env = new docusign.EnvelopeDefinition();
    env.emailSubject = 'Por gentileza, análise e assine o documento';    
    let doc1 = new docusign.Document();
    let doc1b64 = Buffer.from(docPdfBytes).toString('base64');
    
    doc1.documentBase64 = doc1b64;
    doc1.name = 'Lorem Ipsum'; 
    doc1.fileExtension = 'pdf';
    doc1.documentId = '3';
    env.documents = [doc1];
    
    let signer1 = docusign.Signer.constructFromObject({
        email: args.signerEmail,
        name: args.signerName,
        clientUserId: args.signerClientId,
        recipientId: 1
    });

    let signHere1 = docusign.SignHere.constructFromObject({anchorString: '/sn1/', anchorYOffset: '10', anchorUnits: 'pixels', anchorXOffset: '20'});
    let signer1Tabs = docusign.Tabs.constructFromObject({ signHereTabs: [signHere1]});
    signer1.tabs = signer1Tabs;
    let recipients = docusign.Recipients.constructFromObject({signers: [signer1]});
    env.recipients = recipients;
    env.status = 'sent';
    return env;
}

function makeRecipientViewRequest(args) {    

    let viewRequest = new docusign.RecipientViewRequest();
    viewRequest.returnUrl = args.dsReturnUrl + "?state=123";
    viewRequest.authenticationMethod = 'none';
    viewRequest.email = args.signerEmail;
    viewRequest.userName = args.signerName;
    viewRequest.clientUserId = args.signerClientId;
    viewRequest.pingFrequency = 600;     
    viewRequest.pingUrl = args.dsPingUrl;

    return viewRequest
}

eg001EmbeddedSigning.getController = (req, res) => {
    console.log(req.dsAuth);    
    let tokenOK = req.dsAuth.checkToken();
    if (tokenOK) {
        res.render('pages/examples/eg001EmbeddedSigning', {
            eg: eg, csrfToken: req.csrfToken(),
            title: "Desafio Vista",
            sourceFile: path.basename(__filename),
            sourceUrl: dsConfig.githubExampleUrl + path.basename(__filename),
            documentation: dsConfig.documentation + eg,
            showDoc: dsConfig.documentation
        });
    } else {        
        req.dsAuth.setEg(req, eg);
        res.redirect(mustAuthenticate);
    }
}

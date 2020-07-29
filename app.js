	/**
	 *
	 * Copyright 2015 IBM Corp. All Rights Reserved.
	 *
	 * Licensed under the Apache License, Version 2.0 (the "License");
	 * you may not use this file except in compliance with the License.
	 * You may obtain a copy of the License at
	 *
	 *      http://www.apache.org/licenses/LICENSE-2.0
	 *
	 * Unless required by applicable law or agreed to in writing, software
	 * distributed under the License is distributed on an "AS IS" BASIS,
	 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	 * See the License for the specific language governing permissions and
	 * limitations under the License.
	 */
	'use strict';

	var express = require('express'); // app server
	var cookieParser = require('cookie-parser'); //Cookies
	var bodyParser = require('body-parser'); // parser for post requests
	var AssistantV2 = require('ibm-watson/assistant/v2'); // watson sdk


	var request = require('request');
	const path = require('path');
	const multer = require('multer');
	const fs = require('fs');
	var cors = require('cors');
	const cryptoRandomString = require('crypto-random-string');
	
	const dotenvJSON = require("dotenv-json");
	dotenvJSON({ path: "./env.json"});
	var envData = fs.readFileSync("./env.json",{encoding:'utf8'});
	var parsedEnvData = JSON.parse(envData);
//	var envData = require("./env.json");
//	var parsedEnvData = JSON.stringify(envData);
	console.log(parsedEnvData);
	var token = "";

	var app = express();
	const enstr = cryptoRandomString({
	        length: 36,
	        type: 'url-safe'
	    });
	app.use(cookieParser());
	const {
	    IamAuthenticator,
	    BearerTokenAuthenticator
	} = require('ibm-watson/auth');

	app.all('/', function(req, res, next) {
	    console.log('Accessing the secret section ...', req.query.authHeader);
	    token = req.query.authHeader;
	    res.cookie('authToken', token);	    
	    res.cookie(token, enstr);	   
	    next(); // pass control to the next handler

	})

	require('./health/health')(app);
	//Bootstrap application settings
	app.use(bodyParser.urlencoded({
	    extended: true
	}));
	app.use(express.static(path.join(__dirname + '/public')));
	app.use(bodyParser.json());
	app.set('view engine', 'ejs');
	app.use(cors());

	app.use(function(req, res, next) {
	    res.header('Access-Control-Allow-Origin', 'http://10.10.1.40:3000'); // update to match the domain you will make the request from
	    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
	   /*  var cookie = req.cookies.authheader;
	    var cookie = req.cookies.authToken;	  */   
	    next();
	});
	
	let authenticator;
	if (process.env.ASSISTANT_IAM_APIKEY) {
	    authenticator = new IamAuthenticator({
	        apikey: process.env.ASSISTANT_IAM_APIKEY
	    });
	} else if (process.env.BEARER_TOKEN) {
	    authenticator = new BearerTokenAuthenticator({
	        bearerToken: process.env.BEARER_TOKEN
	    });
	}

	var assistant = new AssistantV2({
	    version: process.env.WATSON_VERSION,
	    authenticator: authenticator,
	    url: process.env.ASSISTANT_URL,
	    disableSslVerification: process.env.DISABLE_SSL_VERIFICATION === 'true' ? true : false
	});

	app.post('/api/message', function(req, res) {
	    let assistantId = process.env.ASSISTANT_ID || '<assistant-id>';
	    if (!assistantId || assistantId === '<assistant-id>') {
	        return res.json({
	            output: {
	                text: 'The app has not been configured with a <b>ASSISTANT_ID</b> environment variable. Please refer to the ' +
	                    '<a href="https://github.com/watson-developer-cloud/assistant-simple">README</a> documentation on how to set this variable. <br>' +
	                    'Once a workspace has been defined the intents may be imported from ' +
	                    '<a href="https://github.com/watson-developer-cloud/assistant-simple/blob/master/training/car_workspace.json">here</a> in order to get a working application.',
	            },
	        });
	    }

	    var textIn = '';

	    if (req.body.input) {
	        textIn = req.body.input.text;
	    }

	    var payload = {
	        assistantId: assistantId,
	        sessionId: req.body.session_id,
	        input: {
	            message_type: 'text',
	            text: textIn,
	            'options': {
	                'return_context': true
	            }
	        },
	    };

	    // Send the input to the assistant service

	    assistant.message(payload, function(err, data) {
	        if (err) {
	            const status = err.code !== undefined && err.code > 0 ? err.code : 500;
	            return res.status(status).json(err);
			}
			 return res.json(data);
	    });
	});
	parsedEnvData=JSON.stringify(parsedEnvData);

	app.get('/api/session', function(req, res) {
	    assistant.createSession({
	            assistantId: process.env.ASSISTANT_ID || '{assistant_id}',
	        },
	        function(error, response) {
	            if (error) {
	                return res.send(error);
	            } else {
	                return res.send({response,parsedEnvData});
	            }
	        }
	    );
	});

	const storage = multer.diskStorage({
		
	    destination: process.env.MULTER_DESTINATION,
	    filename: function(req, file, cb) {
			console.log('inside Storage');			
	        cb(null, file.originalname);
	    }
	});

	const upload = multer({
	    storage: storage
	}).single('filename');

	app.post('/api/upload', (req, res) => {
	    var filep = "";
		console.log('inside Upload APi');
	    upload(req, res, (err) => {
	        if (err) {
	            return res.status(400).send(err);
	        } else {		
		console.log('inside upload method');		
	            if (req.file === undefined) {
					return res.send('not selecting files');
	            }
	            filep = path.join(__dirname, "./public/uploads/" + req.file.filename);
	            var claimNumber = JSON.parse(req.body.claimNumber);
	            const options = {
	                method: "POST",
	                url: process.env.FILE_UPLOAD_API,
	                headers: {
	                    "Content-Type": "multipart/form-data",
	                    'Authorization': req.cookies.authToken
	                },
	                formData: {
	                    "uploadFile": fs.createReadStream(filep),
	                    "claimNumber": claimNumber.claimNumber,
	                    "fileName": req.file.filename,
	           			"propertyData": parsedEnvData
	                }
	            };
	            request(options, function(err, httpResponse, body) {
	                if (err)
	                    return res.status(400).send(err);
	                else
	                    return res.send(body);
	            });
	            fs.unlink(filep, err => console.log(err));
	        }
	    });
	});
	
	var responseData='';
	var callSearchApi = async function(req, res, next) {
		var searchAction =req.query.searchAction;
		var claimNumber=req.query.claimNumber;
		var actionTaken = searchAction.toString().toUpperCase();
		var docApi = process.env[`${actionTaken}_API`];
		var url = searchAction === 'documentSearch' ?  docApi : process.env.SEARCH_API;
		request.post({
	        url: url,
	        headers: {
	            'Authorization': token
			},
			formData: {	                    
	                    "claimNumber": claimNumber,
						"searchAction": actionTaken,
	           			"propertyData": parsedEnvData
	        }
	    }, async function(error, response, body) {
	        if (!error && (response.statusCode == 200 || response.statusCode == 201)) {
				responseData = await JSON.parse(body);				
				next();
	        } else {
				res.status(401).send('auth failed');
	        }
	    });
	};

	app.post('/api/search', (req, res) => {
		var tokenUpdated = token.replace('==', '');
	    var encryptedStr = req.cookies[tokenUpdated];
	    res.send(encryptedStr)
	});
	
	var verifyToken = function(req, res, next) {
	    var tokenStr = req.cookies.authToken;
	    var urlToken = req.query.token;
	    if (tokenStr == undefined || urlToken == undefined) {
	        res.status(401).send('Your dont have permissions to access this page');
	    } else if (tokenStr == null || urlToken == null) {
	        res.status(401).send('Your dont have permissions to access this page');
	    } else {
	        var tokenUpdated = tokenStr.replace('==', '');
	        var encryptedStr = req.cookies[tokenUpdated];
	        if (encryptedStr.trim() != urlToken.trim()) {
	            res.status(401).send('Your dont have permissions to access this page');
	        } else {
	            next();
	        }
	    }
	}

	app.get('/search', verifyToken, callSearchApi,(req, res) => {
			var searchAction =req.query.searchAction;
			var actionTaken = searchAction.toString().toUpperCase();
		    var symbolicName = process.env[`${actionTaken}_SYMBOLIC_NAME`].toString().split(',');
			var columnHeader = process.env[`${actionTaken}_HEADERS`].toString().split(',');
			var title = process.env[`${actionTaken}_TITLE`];
			var exportFlag = process.env[`${actionTaken}_EXPORTFLAG`];
			res.render('Search', {
			        'search': responseData,
			        'symbolicName': symbolicName,
					'columnHeader': columnHeader,
					'Title': title,
					'exportButtonFlag': exportFlag
			});	
	});

	app.post('/api/validateclaim', function(req, res) {
	    var claimNumber = req.body.claimNumber;
	    request.post({
	        url: process.env.VALIDATE_CLAIM_API + claimNumber,
	        headers: {
	            'Authorization': req.cookies.authToken
	        },
			formData: {
	           'propertyData': parsedEnvData
	        }
	    }, function(error, response, body) {
	        if (!error && (response.statusCode == 200 || response.statusCode == 201)) {
	            res.send(body);
	        } else {
	            res.status(400).send(error);
	        }

	    });
	});

	app.post('/api/claimnumber', function(req, res) {
	    var claimNumber = req.body.claimNumber;
	    request.post({
	        url: process.env.CREATE_CLAIM_API + claimNumber,
	        headers: {
	            'Authorization': req.cookies.authToken
	        },
			formData: {
	           'propertyData': parsedEnvData
	        }
	    }, function(error, response, body) {

	        if (!error && (response.statusCode == 200 || response.statusCode == 201)) {
	            res.send(body);
	        } else {
	            res.status(400).send(error);
	        }

	    });
	});

	app.post('/api/createCase', function(req, res) {		
	    var username = process.env.CASEMANAGER_USERNAME;
	    var password = process.env.CASEMANAGER_PASSWORD;
	    var options = {
	        url: process.env.IBM_CREATE_CASE_API,
	        headers: {
	            'Content-type': 'application/json',
	            'Access-Control-Allow-Credential': 'true',
	            'Authorization': req.cookies.authToken
	        },
	        auth: {
	            user: username,
	            password: password
	        },
	        method: 'POST',
	        json: req.body
	    }
	    request(options, function(error, response, body) {
	        if (response.statusCode == 200 || response.statusCode == 201) {
	            res.send(body);
	        } else {
	            res.status(401).send(error);
	        }

	    });
	});
	
	module.exports = app;
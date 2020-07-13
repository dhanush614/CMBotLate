    //The ConversationPanel module is designed to handle
    //all display and behaviors of the conversation column of the app.
    /* eslint no-unused-vars: "off" */
    /* global Api: true, Common: true*/
    var chatBoxElement = null;
    var claimNumber = null;
    var docId=null;
    var envDataJson=null;
    var ConversationPanel = (function() {
        var settings = {
            selectors: {
                chatBox: '#scrollingChat',
                fromUser: '.from-user',
                fromWatson: '.from-watson',
                latest: '.latest'
            },
            authorTypes: {
                user: 'user',
                watson: 'watson'
            }
        };
        var flag = false;
        // Publicly accessible methods defined
        return {
            init: init,
            inputKeyDown: inputKeyDown,
            sendMessage: sendMessage
        };

        // Initialize the module
        function init() {
            chatUpdateSetup();
			
            Api.getSessionId(function(envData) {
			envDataJson=JSON.parse(envData);
                Api.sendRequest('', null);
            });
            setupInputBox();
        }
        // Set up callbacks on payload setters in Api module
        // This causes the displayMessage function to be called when messages are sent / received
        function chatUpdateSetup() {
            var currentRequestPayloadSetter = Api.setRequestPayload;
            Api.setRequestPayload = function(newPayloadStr) {
                currentRequestPayloadSetter.call(Api, newPayloadStr);
                displayMessage(JSON.parse(newPayloadStr), settings.authorTypes.user);
            };

            var currentResponsePayloadSetter = Api.setResponsePayload;
            Api.setResponsePayload = function(newPayloadStr) {
                currentResponsePayloadSetter.call(Api, newPayloadStr);
                flag = false;
                displayMessage(JSON.parse(newPayloadStr).result, settings.authorTypes.watson);
                getContextVar(JSON.parse(newPayloadStr).result);
            };

			

            Api.setErrorPayload = function(newPayload) {
                displayMessage(newPayload, settings.authorTypes.watson);
            };
        }

        // Set up the input box to underline text as it is typed
        // This is done by creating a hidden dummy version of the input box that
        // is used to determine what the width of the input text should be.
        // This value is then used to set the new width of the visible input box.
        function setupInputBox() {
            var input = document.getElementById('textInput');
            var dummy = document.getElementById('textInputDummy');
            var minFontSize = 14;
            var maxFontSize = 16;
            var minPadding = 4;
            var maxPadding = 6;

            // If no dummy input box exists, create one
            if (dummy === null) {
                var dummyJson = {
                    'tagName': 'div',
                    'attributes': [{
                        'name': 'id',
                        'value': 'textInputDummy'
                    }]
                };

                dummy = Common.buildDomElement(dummyJson);
                document.body.appendChild(dummy);
            }

            function adjustInput() {
                if (input.value === '') {
                    // If the input box is empty, remove the underline
                    input.classList.remove('underline');
                    input.setAttribute('style', 'width:' + '100%');
                    input.style.width = '100%';
                } else {
                    // otherwise, adjust the dummy text to match, and then set the width of
                    // the visible input box to match it (thus extending the underline)
                    input.classList.add('underline');
                    var txtNode = document.createTextNode(input.value);
                    ['font-size', 'font-style', 'font-weight', 'font-family', 'line-height',
                        'text-transform', 'letter-spacing'
                    ].forEach(function(index) {
                        dummy.style[index] = window.getComputedStyle(input, null).getPropertyValue(index);
                    });
                    dummy.textContent = txtNode.textContent;

                    var padding = 0;
                    var htmlElem = document.getElementsByTagName('html')[0];
                    var currentFontSize = parseInt(window.getComputedStyle(htmlElem, null).getPropertyValue('font-size'), 10);
                    if (currentFontSize) {
                        padding = Math.floor((currentFontSize - minFontSize) / (maxFontSize - minFontSize) *
                            (maxPadding - minPadding) + minPadding);
                    } else {
                        padding = maxPadding;
                    }

                    var widthValue = (dummy.offsetWidth + padding) + 'px';
                    input.setAttribute('style', 'width:100%');
                    input.style.width = '100%';
                }
            }

            // Any time the input changes, or the window resizes, adjust the size of the input box
            input.addEventListener('input', adjustInput);
            window.addEventListener('resize', adjustInput);

            // Trigger the input event once to set up the input box and dummy element
            Common.fireEvent(input, 'input');
        }

        // Display a user or Watson message that has just been sent/received
        function displayMessage(newPayload, typeValue) {
            var isUser = isUserMessage(typeValue);
            //var textExists = newPayload.generic;
            if ((newPayload.output && newPayload.output.generic) || newPayload.input) {
                // Create new message generic elements
                var responses = buildMessageDomElements(newPayload, isUser);
                chatBoxElement = document.querySelector(settings.selectors.chatBox);
                var previousLatest = chatBoxElement.querySelectorAll((isUser ? settings.selectors.fromUser : settings.selectors.fromWatson) +
                    settings.selectors.latest);
                // Previous "latest" message is no longer the most recent
                if (previousLatest) {
                    Common.listForEach(previousLatest, function(element) {
                        element.classList.remove('latest');
                    });
                }
                setResponse(responses, isUser, chatBoxElement, 0, true);
            }
        }

        // Recurisive function to add responses to the chat area
        function setResponse(responses, isUser, chatBoxElement, index, isTop) {
            if (index < responses.length) {
                if (!flag) {
                    var res = responses[index];
                    if (res.type !== 'pause') {
                        var currentDiv = getDivObject(res, isUser, isTop);
                        chatBoxElement.appendChild(currentDiv);
                        // Class to start fade in animation
                        currentDiv.classList.add('load');
                        // Move chat to the most recent messages when new messages are added
                        setTimeout(function() {
                            // wait a sec before scrolling
                            scrollToChatBottom();
                        }, 1000);
                        setResponse(responses, isUser, chatBoxElement, index + 1, false);
                    } else {
                        var userTypringField = document.getElementById('user-typing-field');
                        if (res.typing) {
                            userTypringField.innerHTML = 'Request is in Progress...';
                        }
                        setTimeout(function() {
                            userTypringField.innerHTML = '';
                            setResponse(responses, isUser, chatBoxElement, index + 1, isTop);
                        }, res.time);
                    }
                }
            } else {
                if (responses.length != 0) {
                    if (responses[0].innerhtml == "Please wait your case is being created") {
                        var url = '/api/createCase';
                        var http = new XMLHttpRequest();
                        http.open('POST', url, true);
                        http.setRequestHeader('Content-type', 'application/json');
                        http.responseType = 'json';
                        http.onreadystatechange = function() {
                            if ((http.readyState === XMLHttpRequest.DONE || http.readyState === XMLHttpRequest.HEADERS_RECEIVED) && (http.status === 200 || http.status === 201) && http.response) {
                                flag = true;                               
                                sendMessage(http.response.CaseFolderId);                                
                            } else if (http.readyState === XMLHttpRequest.DONE && http.status !== 200 && http.status !== 201) {
                                Api.setErrorPayload({
                                    'output': {
                                        'generic': [{
                                            'response_type': 'text',
                                            'text': 'I\'m having trouble connecting to the server, please refresh the page'
                                        }],
                                    }
                                });
                            }
                        };
                        var jsonObj = {
                            TargetObjectStore:envDataJson.TARGET_OBJECT_STORE,
                            CaseType:envDataJson.CASE_TYPE,
                            Properties: [{
                                SymbolicName:envDataJson.SYMBOLIC_NAME,
                                Value: claimNumber
                            }]
                        };
                        var params = JSON.stringify(jsonObj);
                        http.send(params);
                    } else if (responses[0].innerhtml === "Please upload your document") {
                        flag = false;
                        var documnetDiv = document.createElement('div');
                        documnetDiv.setAttribute("id", "myDiv");
                        documnetDiv.className = "fileUpload";
                        chatBoxElement.appendChild(documnetDiv);


                        var formDiv = document.createElement("FORM");
                        formDiv.setAttribute("id", "myForm");
                        formDiv.setAttribute("action", "/api/upload");
                        formDiv.setAttribute("enctype", "multipart/form-data");
                        formDiv.setAttribute("method", "post");
                        document.getElementById("myDiv").appendChild(formDiv);

                        var inputFile = document.createElement("INPUT");
                        var label = document.createElement('LABEL');
                        inputFile.setAttribute("type", "file");
                        inputFile.setAttribute("name", "filename");
                        inputFile.setAttribute("id", "uploadedFile");
                        label.setAttribute("for", "uploadedFile");
                        label.className = "btn-2";
                        label.innerHTML = "Choose";
                        document.getElementById("myDiv").appendChild(inputFile);
                        document.getElementById("myDiv").appendChild(label);

                        var inputSubmit = document.createElement("INPUT");
                        inputSubmit.setAttribute("type", "submit");
                        inputSubmit.setAttribute("value", "Upload");
                        inputSubmit.setAttribute("id", "uploadButton");
                        document.getElementById("myDiv").appendChild(inputSubmit);

                        var p = document.createElement("div");
                        p.setAttribute("id", "fileNameP");
                        var input = document.getElementById("uploadedFile");

                        input.addEventListener('change', showFileName);

                        function showFileName(event) {

                            var input = event.srcElement;

                            var fileName = input.files[0].name;

                            p.textContent = 'File name: ' + fileName;
                            setTimeout(function() {
                                scrollToChatBottom();
                            }, 1000);
                        }
                        var br = document.createElement("BR");
                        document.getElementById("myDiv").appendChild(br);
                        document.getElementById("myDiv").appendChild(p);

                        var classes = [(isUser ? 'from-user' : 'from-watson'), 'latest', (isTop ? 'top' : 'sub')];

                        for (var i = 0; i < classes.length; i++) {
                            documnetDiv.classList.add(classes[i]);
                        }

                        documnetDiv.classList.add('load');

                        setTimeout(function() {
                            scrollToChatBottom();
                        }, 1000);

                        document.getElementById("uploadButton").addEventListener("click", fileToApp);
                    } else if (responses[0].innerhtml.includes('Please wait your document is being attached to claim number')) {
                        flag = true;
                        sendMessage(docId);
                    } else if (responses[0].innerhtml.includes("Thanks")) {
                        flag = false;
                        var indexNum = responses[0].innerhtml.indexOf(".");
                        claimNumber = responses[0].innerhtml.substring(58, indexNum);
                    } else {
                        flag = false;
                    }
                }
                //till here
            }
        }
        function  buildSearchResultPage(searchAction,actionToken){
                    var searchDiv = document.createElement('div');
                    searchDiv.className = 'caseSearch';
                    var p = document.createElement('p');
                    //var a = document.createElement('a');
                    // a.href="/caseSearch";
                    p.innerHTML = `click to view ${searchAction} details`;
                    //p.appendChild(a);
                    searchDiv.appendChild(p);
                    chatBoxElement.appendChild(searchDiv);
                    p.onclick = function() {
                        openCase('/search?'+searchAction+'='+actionToken);
                    };

                    function openCase(url) {
                        return window.open(url);
                    }
                    var classe = [(isUser ? 'from-user' : 'from-watson'), 'latest', (isTop ? 'top' : 'sub')];

                    for (var j = 0; j < classe.length; j++) {
                        searchDiv.classList.add(classe[j]);
                    }
                    searchDiv.classList.add('load');
                    setTimeout(function() {
                        scrollToChatBottom();
                    }, 10);
        }

        function getContextVar(newPayloadObj) {
		
            if (newPayloadObj.hasOwnProperty('context')) {
                if (newPayloadObj.context.hasOwnProperty('skills')) {
                    if (newPayloadObj.context.skills['main skill'].hasOwnProperty('user_defined')) {
                        if (newPayloadObj.context.skills['main skill'].user_defined.hasOwnProperty('Claim_Number')) {
                            claimNumber = newPayloadObj.context.skills['main skill'].user_defined.Claim_Number
                        }
                        if (newPayloadObj.context.skills['main skill'].user_defined.hasOwnProperty('navigation')) {
                            if (newPayloadObj.context.skills['main skill'].user_defined.navigation === 'Verifying claim number') {
                                var url = '/api/validateclaim';
                                var http = new XMLHttpRequest();
                                http.open('POST', url, true);
                                http.setRequestHeader('Content-type', 'application/json');
                                http.onreadystatechange = function() {
                                    if (http.readyState === XMLHttpRequest.DONE && http.status === 200 && http.responseText) {
                                        //flag = true;
                                        //sendMessage(http.responseText);
                                        if (!http.responseText.includes('Error from service')) {
                                            flag = true;
                                            sendMessage(http.responseText);
                                        }
                                        let errmsg = http.responseText.split(':')[1];
                                        Api.setErrorPayload({
                                            'output': {
                                                'generic': [{
                                                    'response_type': 'text',
                                                    'text': errmsg
                                                }]
                                            }
                                        });
                                    } else if (http.readyState === XMLHttpRequest.DONE && http.status !== 200) {
                                        Api.setErrorPayload({
                                            'output': {
                                                'generic': [{
                                                    'response_type': 'text',
                                                    'text': 'I\'m having trouble connecting to the server, please refresh the page'
                                                }],
                                            }
                                        });
                                    }
                                };

                                var jsonObj = {
                                    claimNumber: claimNumber
                                };

                                var paramsJson = JSON.stringify(jsonObj);
                                http.send(paramsJson);

                            } else if (newPayloadObj.context.skills['main skill'].user_defined.navigation === 'Case export is in Progress') {
                                search('claimSearch');
                            }else if (newPayloadObj.context.skills['main skill'].user_defined.navigation === 'Case status export is in Progress') {
                                search('claimStatus');
                            }else if (newPayloadObj.context.skills['main skill'].user_defined.navigation === 'Case history export is in Progress') {
                                search('claimHistory');
                            } 
                            else if (newPayloadObj.context.skills['main skill'].user_defined.navigation === 'Document Search is in Progress') {
                                var url = '/api/documentSearch';
                                var docSearchAction='documentSearch';
                                var http = new XMLHttpRequest();
                                http.open('POST', url, true);
                                http.setRequestHeader('Content-type', 'application/json');
                                http.onreadystatechange = function() {
                                    if (http.readyState === XMLHttpRequest.DONE && http.status === 200 && http.response) {
                                        flag = false;                                       
                                        var documentSearchDiv = document.createElement('div');
                                        documentSearchDiv.className = 'documentSearch';
                                        documentSearchDiv.setAttribute('id', 'searchDiv');
                                        var searchList = document.createElement('ul');
                                        documentSearchDiv.appendChild(searchList);
                                        searchList.className += 'SearchList';
                                        var parsedData = JSON.parse(http.response);
                                        var parsedBody = JSON.parse(parsedData.body);
                                        var dataLength = parsedBody.length;
                                        if(dataLength<=10){
                                        parsedBody.map((el) => {
                                            var li = document.createElement('li');
                                            li.className += 'documentLi';
                                            li.innerHTML = el.documentName;
                                            //a.setAttribute("onclick",openDocument(el.documentUrl));
                                            li.onclick = function() {
                                                openDocument(el.documentUrl)
                                            }
                                            searchList.appendChild(li);
                                        });

                                        function openDocument(url) {
                                            return window.open(url);
                                        }

                                        chatBoxElement.appendChild(documentSearchDiv);

                                        var classe = [(isUser ? 'from-user' : 'from-watson'), 'latest', (isTop ? 'top' : 'sub')];
                                        for (var j = 0; j < classe.length; j++) {
                                            documentSearchDiv.classList.add(classe[j]);
                                        }
                                        documentSearchDiv.classList.add('load');
                                        scrollToChatBottom();
                                            setTimeout(function() {
                                        }, 10);
                                      }else{
                                        var encryptedToken=parsedData.encryptedStr;
                                         buildSearchResultPage(docSearchAction,encryptedToken);
                                     }
                                    } else if (http.readyState === XMLHttpRequest.DONE && http.status !== 200 && http.status !== 201) {
                                        Api.setErrorPayload({
                                            'output': {
                                                'generic': [{
                                                    'response_type': 'text',
                                                    'text': 'I\'m having trouble connecting to the server, please refresh the page'
                                                }],
                                            }
                                        });
                                    }
                                };

                                var jsonObj = {
                                    claimNumber: claimNumber,
                                    action: docSearchAction
                                };
                                var params = JSON.stringify(jsonObj);
                                http.send(params);
                            }
                        }
                    }
                }
            }
        }

        function search(searchAction) {
            var http = new XMLHttpRequest();
            var url = '/api/search';
            http.open('POST', url, true);
            http.setRequestHeader('Content-type', 'application/json');
            http.onreadystatechange = function() {
                if (http.readyState === XMLHttpRequest.DONE && http.status === 200 && http.responseText) {
                    flag = false;
                    buildSearchResultPage(searchAction,http.responseText);  
                } else if (http.readyState === XMLHttpRequest.DONE && http.status !== 200 && http.status !== 201) {
                    Api.setErrorPayload({
                        'output': {
                            'generic': [{
                                'response_type': 'text',
                                'text': 'I\'m having trouble connecting to the server, please refresh the page'
                            }],
                        }
                    });
                }
            };
            var jsonObj = {
                claimNumber: claimNumber,
                action:searchAction
            };
            var params = JSON.stringify(jsonObj);
            http.send(params);

        }

        function fileToApp() {
            var fileLength = document.getElementById('uploadedFile').files.length;
            if (fileLength > 0) {
                var uploadedFileObj = document.getElementById('uploadedFile').files[0];
                const formData = new FormData();
                formData.append('filename', uploadedFileObj);
                var jsonObj = {
                    claimNumber: claimNumber,
                    filename: uploadedFileObj
                };
                var paramsJson = JSON.stringify(jsonObj);
                formData.append('claimNumber', paramsJson);
                var http = new XMLHttpRequest();
                http.open('POST', '/api/upload', true);
                http.onreadystatechange = function() {
                    if ((http.readyState === XMLHttpRequest.DONE || http.readyState === XMLHttpRequest.HEADERS_RECEIVED) && (http.status === 200 || http.status === 201) && http.responseText != 'not selecting files' && http.responseText != '') {

                        flag = true;
                        sendMessage("Y");
                        docId = http.responseText;
                    } else if (http.readyState === XMLHttpRequest.DONE && (http.status === 200 || http.status === 201) && http.responseText == 'not selecting files' && http.responseText != '') {
                        {
                            Api.setErrorPayload({
                                'output': {
                                    'generic': [{
                                        'response_type': 'text',
                                        'text': 'Please select a document'
                                    }],
                                }
                            });
                        }
                    } else if (http.readyState === XMLHttpRequest.DONE && http.status !== 200 && http.status !== 201) {
                        Api.setErrorPayload({
                            'output': {
                                'generic': [{
                                    'response_type': 'text',
                                    'text': 'I\'m having trouble connecting to the server, please refresh the page'
                                }],
                            }
                        });
                    }
                };


                http.send(formData);
            }
        }
        // Constructs new DOM element from a message
        function getDivObject(res, isUser, isTop) {
            var classes = [(isUser ? 'from-user' : 'from-watson'), 'latest', (isTop ? 'top' : 'sub')];
            var messageJson = {
                // <div class='segments'>
                'tagName': 'div',
                'classNames': ['segments'],
                'children': [{
                    // <div class='from-user/from-watson latest'>
                    'tagName': 'div',
                    'classNames': classes,
                    'children': [{
                        // <div class='message-inner'>
                        'tagName': 'div',
                        'classNames': ['message-inner'],
                        'children': [{
                            // <p>{messageText}</p>
                            'tagName': 'p',
                            'text': res.innerhtml
                        }]
                    }]
                }]
            };
            return Common.buildDomElement(messageJson);
        }

        // Checks if the given typeValue matches with the user "name", the Watson "name", or neither
        // Returns true if user, false if Watson, and null if neither
        // Used to keep track of whether a message was from the user or Watson
        function isUserMessage(typeValue) {
            if (typeValue === settings.authorTypes.user) {
                return true;
            } else if (typeValue === settings.authorTypes.watson) {
                return false;
            }
            return null;
        }

        function getOptions(optionsList, preference) {
            var list = '';
            var i = 0;
            if (optionsList !== null) {
                if (preference === 'text') {
                    list = '<ul>';
                    for (i = 0; i < optionsList.length; i++) {
                        if (optionsList[i].value) {
                            list += '<li><div class="options-list" onclick="ConversationPanel.sendMessage(\'' +
                                optionsList[i].value.input.text + '\');" >' + optionsList[i].label + '</div></li>';
                        }
                    }
                    list += '</ul>';
                } else if (preference === 'button') {
                    list = '<br>';
                    for (i = 0; i < optionsList.length; i++) {
                        if (optionsList[i].value) {
                            var item = '<div class="options-button" onclick="ConversationPanel.sendMessage(\'' +
                                optionsList[i].value.input.text + '\');" >' + optionsList[i].label + '</div>';
                            list += item;
                        }
                    }
                }
            }
            return list;
        }

        function getResponse(responses, gen) {
            var title = '',
                description = '';
            if (gen.hasOwnProperty('title')) {
                title = gen.title;
            }
            if (gen.hasOwnProperty('description')) {
                description = '<div>' + gen.description + '</div>';
            }
            if (gen.response_type === 'image') {
                var img = '<div><img src="' + gen.source + '" width="300"></div>';
                responses.push({
                    type: gen.response_type,
                    innerhtml: title + description + img
                });
            } else if (gen.response_type === 'text') {
                responses.push({
                    type: gen.response_type,
                    innerhtml: gen.text
                });
            } else if (gen.response_type === 'pause') {
                responses.push({
                    type: gen.response_type,
                    time: gen.time,
                    typing: gen.typing
                });
            } else if (gen.response_type === 'option') {
                var preference = 'text';
                if (gen.hasOwnProperty('preference')) {
                    preference = gen.preference;
                }

                var list = getOptions(gen.options, preference);
                responses.push({
                    type: gen.response_type,
                    innerhtml: title + description + list
                });
            }
        }

        // Constructs new generic elements from a message payload
        function buildMessageDomElements(newPayload, isUser) {
            var textArray = isUser ? newPayload.input.text : newPayload.output.text;
            if (Object.prototype.toString.call(textArray) !== '[object Array]') {
                textArray = [textArray];
            }

            var responses = [];

            if (newPayload.hasOwnProperty('output')) {
                if (newPayload.output.hasOwnProperty('generic')) {

                    var generic = newPayload.output.generic;

                    generic.forEach(function(gen) {
                        getResponse(responses, gen);
                    });
                }
            } else if (newPayload.hasOwnProperty('input')) {
                var input = '';
                textArray.forEach(function(msg) {
                    input += msg + ' ';
                });
                input = input.trim()
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;');

                if (input.length !== 0) {
                    responses.push({
                        type: 'text',
                        innerhtml: input
                    });
                }
            }
            return responses;
        }

        // Scroll to the bottom of the chat window
        function scrollToChatBottom() {
            var scrollingChat = document.querySelector('#scrollingChat');
            scrollingChat.scrollTop = scrollingChat.scrollHeight;
        }

        function sendMessage(text) {
            // Send the user message

            Api.sendRequest(text);
        }

        // Handles the submission of input
        function inputKeyDown(event, inputBox) {
            // Submit on enter key, dis-allowing blank messages
            if (event.keyCode === 13 && inputBox.value) {
                sendMessage(inputBox.value);
                // Clear input box for further messages
                inputBox.value = '';
                Common.fireEvent(inputBox, 'input');
            }
        }
    })();
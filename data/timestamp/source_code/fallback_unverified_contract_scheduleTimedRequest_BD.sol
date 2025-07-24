/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimedRequest
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence through a multi-transaction timed request system. The vulnerability manifests in multiple ways: 1) Users can schedule oracle requests for future execution, but miners can manipulate block timestamps to execute requests up to ~15 seconds earlier than intended, 2) The cancellation refund logic depends on timestamp comparison, allowing manipulation of refund amounts, and 3) The system requires multiple transactions (schedule → execute/cancel) creating a stateful vulnerability that persists across transactions. This creates opportunities for timestamp manipulation attacks that require multiple function calls to exploit.
 */
pragma solidity ^0.4.18;

// EthernityFinancialOracle v0.2
// @ethernity.live

contract Caller {
    function EFOcallBack(string _response);
}

contract EthernityFinancialOracle{
    
    address public owner;
    address public oracleAddress;
    uint public collectedFee; 
    uint public feePrice = 0.0005 ether;
    uint public gasLimit = 50000;
    uint public gasPrice = 40000000000 wei;
    
    struct User {
    	string response;
    	bool callBack;
    	bool asked;
    	uint balance;
    	bool banned;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables for timed requests (add to contract state)
    struct TimedRequest {
        string coin;
        string againstCoin;
        uint scheduledTime;
        uint gasPrice;
        uint gasLimit;
        bool callBack;
        bool executed;
        bool active;
    }

    mapping(address => TimedRequest) public timedRequests;

    // Schedule a request to be executed at a specific time
    function scheduleTimedRequest(string _coin, string _againstCoin, uint _delaySeconds, bool _callBack, uint _gasPrice, uint _gasLimit) payable receivePayment notBanned {
        require(_delaySeconds >= 60); // Minimum 1 minute delay
        require(_delaySeconds <= 86400); // Maximum 24 hours delay
        
        // Cancel any existing timed request
        timedRequests[msg.sender].active = false;
        
        // Calculate scheduled execution time
        uint scheduledTime = now + _delaySeconds;
        
        // Store the timed request
        timedRequests[msg.sender] = TimedRequest({
            coin: _coin,
            againstCoin: _againstCoin,
            scheduledTime: scheduledTime,
            gasPrice: _gasPrice,
            gasLimit: _gasLimit,
            callBack: _callBack,
            executed: false,
            active: true
        });
    }
    
    // Execute a previously scheduled request
    function executeTimedRequest() payable receivePayment notBanned {
        TimedRequest storage request = timedRequests[msg.sender];
        
        require(request.active);
        require(!request.executed);
        
        // VULNERABILITY: Using block.timestamp (now) for time-dependent logic
        // Miners can manipulate timestamp within ~15 seconds
        // This creates a window where requests can be executed earlier than intended
        require(now >= request.scheduledTime);
        
        // Mark as executed
        request.executed = true;
        request.active = false;
        
        // Execute the actual oracle request
        (uint finalGasPrice, uint finalGasLimit) = payToOracle(request.gasPrice, request.gasLimit);
        users[msg.sender].callBack = request.callBack;
        users[msg.sender].asked = true;
        
        Request(request.coin, request.againstCoin, msg.sender, finalGasPrice, finalGasLimit);
    }
    
    // Cancel a scheduled request and get partial refund
    function cancelTimedRequest() {
        TimedRequest storage request = timedRequests[msg.sender];
        
        require(request.active);
        require(!request.executed);
        
        // VULNERABILITY: Time-based cancellation logic
        // If cancelled before scheduled time, user gets 90% refund
        // If cancelled after scheduled time, user gets 50% refund
        uint refundPercentage;
        if (now < request.scheduledTime) {
            refundPercentage = 90;
        } else {
            refundPercentage = 50;
        }
        
        uint requestCost = getPrice(request.gasPrice, request.gasLimit);
        uint refundAmount = (requestCost * refundPercentage) / 100;
        
        // Cancel the request
        request.active = false;
        
        // Process refund
        users[msg.sender].balance += refundAmount;
        collectedFee += (requestCost - refundAmount);
    }
    // === END FALLBACK INJECTION ===

    mapping(address => User) public users;

    
    modifier onlyOwner{
        require(msg.sender == owner);
        _;
    }

    modifier onlyOracle{
        require(msg.sender == oracleAddress);
        _;
    }

    modifier onlyOwnerOrOracle {
    	require(msg.sender == owner || msg.sender == oracleAddress);
    	_;
    }

    modifier notBanned {
        require( users[msg.sender].banned == false );
        _;
    }

    modifier receivePayment {
        users[msg.sender].balance = users[msg.sender].balance + msg.value;
        _;
    }

    event Request (string _coin , string _againstCoin , address _address , uint _gasPrice , uint _gasLimit );
    event Response (address _address , string _response);
    event Error (string _error);
    

    // Main constructor
    function EthernityFinancialOracle() {
        owner = msg.sender;
        oracleAddress = msg.sender; // 0xfb509f6900d0326520c8f88e8f12c83459a199ec;
    }   

    // Payable to receive payments and stores into the mapping through modifier
    function () payable receivePayment {
    }

    // REQUESTS
    
    function requestEtherToUSD(bool _callBack , uint _gasPrice , uint _gasLimit) payable receivePayment notBanned {
        (_gasPrice , _gasLimit) = payToOracle (_gasPrice , _gasLimit);
        users[msg.sender].callBack = _callBack;
        users[msg.sender].asked = true;
        Request ('ETH', 'USD', msg.sender , _gasPrice , _gasLimit );
    }
    
    function requestCoinToUSD(string _coin , bool _callBack , uint _gasPrice , uint _gasLimit) payable receivePayment notBanned {
    	(_gasPrice , _gasLimit) = payToOracle (_gasPrice , _gasLimit);
        users[msg.sender].callBack = _callBack;
        users[msg.sender].asked = true;
        Request (_coin, 'USD', msg.sender , _gasPrice , _gasLimit );
    }
    
    function requestRate(string _coin, string _againstCoin , bool _callBack , uint _gasPrice , uint _gasLimit) payable receivePayment notBanned {
    	(_gasPrice , _gasLimit) = payToOracle (_gasPrice , _gasLimit);
        users[msg.sender].callBack = _callBack;
        users[msg.sender].asked = true;
        Request (_coin, _againstCoin, msg.sender , _gasPrice , _gasLimit );
    }


    function getRefund() {
        if (msg.sender == owner) {
            uint a = collectedFee;
            collectedFee = 0; 
            require(owner.send(a));
        } else {
	        uint b = users[msg.sender].balance;
	        users[msg.sender].balance = 0;
	        require(msg.sender.send(b));
	    	}
    }


    // GETTERS

    function getResponse() public constant returns(string _response){
        return users[msg.sender].response;
    }

    function getPrice(uint _gasPrice , uint _gasLimit) public constant returns(uint _price) {
        if (_gasPrice == 0) _gasPrice = gasPrice;
        if (_gasLimit == 0) _gasLimit = gasLimit;
    	assert(_gasLimit * _gasPrice / _gasLimit == _gasPrice); // To avoid overflow exploitation
    	return feePrice + _gasLimit * _gasPrice;
    }

    function getBalance() public constant returns(uint _balance) {
    	return users[msg.sender].balance;
    }

    function getBalance(address _address) public constant returns(uint _balance) {
		return users[_address].balance;
    }



    // SET RESPONSE FROM ORACLE
    function setResponse (address _user, string _result) onlyOracle {

		require( users[_user].asked );
		users[_user].asked = false;

    	if ( users[_user].callBack ) {
    		// Callback function: passive, expensive, somewhat private
        	Caller _caller = Caller(_user);
        	_caller.EFOcallBack(_result);
    		} else {
    	// Mapping: active, cheap, public
        users[_user].response = _result;
        Response( _user , _result );
    	}

    }


    // INTERNAL FUNCTIONS

    function payToOracle (uint _gasPrice , uint _gasLimit) internal returns(uint _price , uint _limit) {
        if (_gasPrice == 0) _gasPrice = gasPrice;
        if (_gasLimit == 0) _gasLimit = gasLimit;

        uint gp = getPrice(_gasPrice,_gasLimit);

        require (users[msg.sender].balance >= gp );

        collectedFee += feePrice;
        users[msg.sender].balance -= gp;

        require(oracleAddress.send(gp - feePrice));
        return(_gasPrice,_gasLimit);
    }


    // ADMIN FUNCTIONS
    
    function changeOwner(address _newOwner) onlyOwner {
        owner = _newOwner;
    }

    function changeOracleAdd(address _newOracleAdd) onlyOwner {
        oracleAddress = _newOracleAdd;
    }

    function setFeePrice(uint _feePrice) onlyOwner {
        feePrice = _feePrice;
    }

    function setGasPrice(uint _gasPrice) onlyOwnerOrOracle {
    	gasPrice = _gasPrice;
    }

    function setGasLimit(uint _gasLimit) onlyOwnerOrOracle {
    	gasLimit = _gasLimit;
    }

    function emergencyFlush() onlyOwner {
        require(owner.send(this.balance));
    }

    function ban(address _user) onlyOwner{
        users[_user].banned = true;
    }
    
    function desBan(address _user) onlyOwner{
        users[_user].banned = false;
    }
}

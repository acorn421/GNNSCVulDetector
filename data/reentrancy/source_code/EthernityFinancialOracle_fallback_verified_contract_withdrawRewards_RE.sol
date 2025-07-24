/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawRewards
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This vulnerability implements a classic reentrancy attack pattern that requires multiple transactions to exploit. The vulnerability exists in the withdrawRewards() function where an external call is made before updating the user's reward balance. An attacker must first accumulate rewards through claimDailyReward() or have rewards added by the owner, then exploit the reentrancy by calling withdrawRewards() from a malicious contract that re-enters the function during the external call, allowing multiple withdrawals of the same reward amount. The rewardWithdrawalInProgress mapping attempts to prevent this but is bypassed because the external call happens before the state is properly updated.
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

    // === FALLBACK INJECTION: Reentrancy ===
    // User reward withdrawal system
    mapping(address => uint) public userRewards;
    mapping(address => bool) public rewardWithdrawalInProgress;
    
    function withdrawRewards() public {
        require(userRewards[msg.sender] > 0, "No rewards to withdraw");
        require(!rewardWithdrawalInProgress[msg.sender], "Withdrawal in progress");
        
        rewardWithdrawalInProgress[msg.sender] = true;
        uint reward = userRewards[msg.sender];
        
        // Vulnerable: external call before state update
        if (msg.sender.call.value(reward)()) {
            userRewards[msg.sender] = 0;
            rewardWithdrawalInProgress[msg.sender] = false;
        } else {
            rewardWithdrawalInProgress[msg.sender] = false;
            revert("Transfer failed");
        }
    }
    
    function addReward(address _user, uint _amount) public onlyOwner {
        userRewards[_user] += _amount;
    }
    
    function claimDailyReward() public {
        require(!users[msg.sender].banned, "User is banned");
        require(userRewards[msg.sender] == 0, "Already has pending rewards");
        
        // Simple daily reward mechanism
        userRewards[msg.sender] = 0.001 ether;
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

/*
 * ===== SmartInject Injection Details =====
 * Function      : getRefund
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: Two new mappings track withdrawal status and amounts across transactions
 * 2. **External Call Before State Update**: The msg.sender.send() call occurs before users[msg.sender].balance is zeroed
 * 3. **Stateful Tracking**: withdrawalInProgress and withdrawalAmount persist between transactions
 * 4. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: User calls getRefund(), triggering send() which can reenter
 *    - Transaction 2+: During the send() callback, user can call getRefund() again
 *    - The original balance hasn't been zeroed yet, so multiple withdrawals are possible
 *    - Each reentrant call sees the original balance amount and can withdraw it again
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Initial Transaction**: User calls getRefund() with balance of 100 ETH
 * 2. **Reentrancy Window**: During msg.sender.send(100), the user's contract receives ETH
 * 3. **Reentrant Calls**: User's contract calls getRefund() again from receive/fallback
 * 4. **State Exploitation**: Since users[msg.sender].balance hasn't been zeroed yet, they can withdraw multiple times
 * 5. **Final State Update**: Only the last successful call updates the balance to 0
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the external call (send) to trigger a callback to the user's contract
 * - The callback enables additional function calls while the original transaction is still executing
 * - State changes are deferred until after the external call completes
 * - Multiple nested calls can exploit the unchanged state before final update
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


    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => bool) public withdrawalInProgress;
    mapping(address => uint) public withdrawalAmount;
    
    function getRefund() {
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (msg.sender == owner) {
            uint a = collectedFee;
            collectedFee = 0; 
            require(owner.send(a));
        } else {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            require(!withdrawalInProgress[msg.sender], "Withdrawal already in progress");
            
            uint b = users[msg.sender].balance;
            require(b > 0, "No balance to withdraw");
            
            // Mark withdrawal as in progress but don't update balance yet
            withdrawalInProgress[msg.sender] = true;
            withdrawalAmount[msg.sender] = b;
            
            // External call before state update - vulnerable to reentrancy
            if (msg.sender.send(b)) {
                // Only update state after successful send
                users[msg.sender].balance = 0;
                withdrawalInProgress[msg.sender] = false;
                withdrawalAmount[msg.sender] = 0;
            } else {
                // Revert the withdrawal tracking on failure
                withdrawalInProgress[msg.sender] = false;
                withdrawalAmount[msg.sender] = 0;
                revert("Transfer failed");
            }
        }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
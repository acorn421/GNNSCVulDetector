/*
 * ===== SmartInject Injection Details =====
 * Function      : createTransaction
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
 * **VULNERABILITY INJECTION ANALYSIS:**
 * 
 * **1. Specific Changes Made:**
 * - Added external call to the transaction recipient (`_to.call()`) before signing the transaction
 * - The external call notifies the recipient about transaction creation via `onTransactionCreated()`
 * - Moved the signing operation to occur AFTER the external call
 * - The external call allows reentrancy back into `createTransaction` while transaction state is partially updated
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 (Setup):** 
 * - Attacker creates malicious contract that implements `onTransactionCreated()` callback
 * - Attacker becomes a signer in the multisig wallet
 * 
 * **Transaction 2 (Trigger):**
 * - Attacker calls `createTransaction()` with their malicious contract as `_to`
 * - During execution: txCount is incremented, transaction is stored
 * - External call to malicious contract's `onTransactionCreated()` is made
 * - Malicious contract reenters `createTransaction()` multiple times
 * - Each reentrant call increments txCount and creates new transactions
 * - Original transaction gets signed with manipulated state
 * 
 * **Transaction 3+ (Exploitation):**
 * - Attacker can now reference transaction IDs that were created during reentrancy
 * - State inconsistencies allow manipulation of transaction confirmation process
 * - Multiple phantom transactions exist with manipulated txCount values
 * 
 * **3. Why Multi-Transaction Exploitation is Required:**
 * - **State Accumulation:** The vulnerability exploits the persistent `txCount` state that accumulates across calls
 * - **Confirmation Dependencies:** The multisig workflow naturally requires multiple transactions from different signers
 * - **Reentrancy Window:** The external call creates a window where state is partially updated but not finalized
 * - **ID Manipulation:** Transaction IDs become inconsistent, requiring multiple transactions to exploit the confusion
 * - **Signature Bypass:** The accumulated state changes can potentially bypass signature requirements across multiple transactions
 * 
 * **4. Realistic Integration:**
 * - The external call appears as a legitimate "notification" feature
 * - Common pattern in DeFi protocols to notify recipients of pending transactions
 * - Maintains original function behavior while introducing subtle vulnerability
 * - The vulnerability is not immediately obvious and could pass code review
 */
// Multi-signature wallet for easily transfers of ETH and ERC20 tokens
// Developed by Phenom.Team <info@phenom.team>
pragma solidity ^0.4.24;

/**
 *   @title ERC20
 *   @dev Standart ERC20 token interface
 */

 /**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {
    address public owner;


    event OwnershipRenounced(address indexed previousOwner);
    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );


      /**
       * @dev The Ownable constructor sets the original `owner` of the contract to the sender
       * account.
       */
    constructor() public {
        owner = msg.sender;
    }

      /**
       * @dev Throws if called by any account other than the owner.
       */
    modifier onlyOwner() {
        require(msg.sender == owner, "msg.sender is not Owner");
        _;
    }

      /**
       * @dev Allows the current owner to transfer control of the contract to a newOwner.
       * @param newOwner The address to transfer ownership to.
       */
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "Owner must not be zero-address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

      /**
       * @dev Allows the current owner to relinquish control of the contract.
       */
    function renounceOwnership() public onlyOwner {
        emit OwnershipRenounced(owner);
        owner = address(0);
    }
}

contract ERC20 {
    uint public totalSupply;

    mapping(address => uint) balances;
    mapping(address => mapping (address => uint)) allowed;

    function balanceOf(address _owner) public view returns (uint);
    function transfer(address _to, uint _value) public returns (bool);
    function transferFrom(address _from, address _to, uint _value) public returns (bool);
    function approve(address _spender, uint _value) public  returns (bool);
    function allowance(address _owner, address _spender) public view returns (uint);

    event Transfer(address indexed _from, address indexed _to, uint _value);
    event Approval(address indexed _owner, address indexed _spender, uint _value);

} 

/// @title Multisignature wallet
contract MultiSigWallet {

    //Events
    event TransactionCreated(uint indexed _txId, uint indexed _timestamp, address indexed _creator);
    event TranscationSended(uint indexed _txId, uint indexed _timestamp);
    event TranscationSigned(uint indexed _txId, uint indexed _timestamp, address indexed _signer);
    event TranscationUnsigned(uint indexed _txId, uint indexed _timestamp, address indexed _signer);
    event Deposit(uint _amount, address indexed _sender);
    
    //Trunsaction struct
    struct Transcation {
        address to;
        address tokenAddress; // if tx is ether transfer  token address equals address(0) 
        uint amount;
        uint confirmations;
        bool done;
        mapping (address => bool) confirmed;
    }

    //adresses of signers
    address[] public signers;
    
    //numbers of signs to perform tx
    uint public requiredConfirmations;
    
    //trancations count
    uint public txCount;
    
    //mappings
    mapping (uint => Transcation) public transactions; // trancations
    mapping (address => bool) isSigner; // signers

    // name of the wallet
    string public name;
    

    modifier onlySigners {
        require(isSigner[msg.sender], "msg.sender is not Signer");
        _;
    } 

    
   /**
    *   @dev Contract constructor sets signers list, required number of confirmations and name of the wallet.
    *   @param _signers                     signers list
    *   @param _requiredConfirmations       required number of confirmations
    *   @param _name                        name of the wallet
    */
    constructor(
        address[] _signers, 
        uint _requiredConfirmations,
        string _name
    ) 
    public {
        require( 
            _requiredConfirmations <= _signers.length && 
            _requiredConfirmations > 0,
            "required confirmations must be > 0 and less than number of signers"
        );
        requiredConfirmations = _requiredConfirmations;
        for (uint i = 0; i < _signers.length; i++) {
            signers.push(_signers[i]);
            isSigner[_signers[i]] = true;
        }
        name = _name;
    }

   /**
    *   @dev Fallback function
    */
    function() public payable {
        require(msg.value > 0, "value must be > 0");
        emit Deposit(msg.value, msg.sender);
    }
    
    function getSigners() public view returns (address[]) {
        return signers;
    }

   /**
    *   @dev Allows to create a new transaction
    */
    function createTransaction(
        address _to, 
        address _tokenAddress,
        uint _amount
    ) 
    public 
    onlySigners {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Create transaction first to get txId
        txCount++;
        uint currentTxId = txCount;
        
        transactions[currentTxId] = Transcation(
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            _to,
            _tokenAddress,
            _amount,
            0,
            false
        );
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        emit TransactionCreated(currentTxId, now, msg.sender);
        
        // External call to notify transaction recipient before signing
        // This allows reentrancy back into createTransaction
        if (_to != address(0)) {
            // Call recipient's notification function if it exists
            // This is vulnerable to reentrancy attacks
            (bool success, ) = _to.call(abi.encodeWithSignature("onTransactionCreated(uint256,address,uint256)", currentTxId, _tokenAddress, _amount));
            // Ignore return value to maintain functionality
        }
        
        // Sign transaction after external call - state can be manipulated during reentrancy
        signTransaction(currentTxId);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

   /**
    *   @dev Allows to sign a transaction
    */
    function signTransaction(uint _txId) public  onlySigners {
        require(!transactions[_txId].confirmed[msg.sender] && _txId <= txCount, "must be a valid unsigned tx");
        transactions[_txId].confirmed[msg.sender] = true;
        transactions[_txId].confirmations++;
        emit TranscationSigned(_txId, now, msg.sender);
        if (transactions[_txId].confirmations >= requiredConfirmations) {
            _sendTransaction(_txId);
      }
    }
    
    function getTransactionsId(
        bool _pending, 
        bool _done,
        bool _tokenTransfers,
        bool _etherTransfers, 
        uint _tailSize
    ) 
    public 
    view returns(uint[] _txIdList) {
        uint[] memory tempList = new uint[](txCount);
        uint count = 0;
        uint id = txCount;
        while(id > 0 && count < _tailSize) {
            if ((_pending && !transactions[id].done || _done && transactions[id].done) && 
                (_tokenTransfers && transactions[id].tokenAddress != address(0) || 
                 _etherTransfers && transactions[id].tokenAddress == address(0))
                ) 
                {
                tempList[count] = id;
                count++;
                }
            id--;
        }
        _txIdList = new uint[](count);
        for (uint i = 0; i < count; i++) {
            _txIdList[i] = tempList[i];
        }
    }

    /*
    *   @dev Allows to check whether tx is signed by signer
    */
    function isSigned(uint _txId, address _signer) 
        public
        view
        returns (bool _isSigned) 
    {
        _isSigned = transactions[_txId].confirmed[_signer];
    }
    
    function unsignTransaction(uint _txId) external onlySigners {
        require(
            transactions[_txId].confirmed[msg.sender] && 
            !transactions[_txId].done,
            "must be a valid signed tx"
        );
        transactions[_txId].confirmed[msg.sender] = false;
        transactions[_txId].confirmations--;
        emit TranscationUnsigned(_txId, now, msg.sender);
    }

    //executing tx
    function _sendTransaction(uint _txId) private {
        require(!transactions[_txId].done, "transaction must not be done");
        transactions[_txId].done = true;
        if ( transactions[_txId].tokenAddress == address(0)) {
            transactions[_txId].to.transfer(transactions[_txId].amount);
        } else {
            ERC20 token = ERC20(transactions[_txId].tokenAddress);
            require(token.transfer(transactions[_txId].to, transactions[_txId].amount), "token transfer failded");
        }
        emit TranscationSended(_txId, now);
    }

}


/// @title Multisignature wallet factory
contract MultiSigWalletCreator is Ownable() {

    // wallets
    mapping(address => bool) public isMultiSigWallet;

    mapping(address => address[]) public wallets;

    mapping(address => uint) public numberOfWallets;

    // information about system
    string public currentSystemInfo;

    event walletCreated(address indexed _creator, address indexed _wallet);

    function createMultiSigWallet(
        address[] _signers, 
        uint _requiredConfirmations,
        string _name
        )
        public
        returns (address wallet)
    {
        wallet = new MultiSigWallet(_signers, _requiredConfirmations, _name);
        isMultiSigWallet[wallet] = true;    
        for (uint i = 0; i < _signers.length; i++) {
            wallets[_signers[i]].push(wallet);
            numberOfWallets[_signers[i]]++;
        }
        emit walletCreated(msg.sender, wallet);
    }

    function setCurrentSystemInfo(string _info) public onlyOwner {
        currentSystemInfo = _info;
    }
}
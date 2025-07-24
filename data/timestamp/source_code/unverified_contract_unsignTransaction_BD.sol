/*
 * ===== SmartInject Injection Details =====
 * Function      : unsignTransaction
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding:
 * 
 * 1. **Persistent State Tracking**: Added `lastUnsignTime` mapping to track when each signer last unsigned a transaction, creating state that persists between transactions.
 * 
 * 2. **Time-based Rate Limiting**: Implemented `unsignCooldownPeriod` that prevents rapid unsigning using `block.timestamp` (now), making the function vulnerable to miner timestamp manipulation.
 * 
 * 3. **Time-sensitive Confirmation Requirements**: Added logic that reduces required confirmations for older transactions based on `txAge` calculated from stored timestamps, allowing miners to manipulate when transactions become easier to cancel.
 * 
 * 4. **Automatic Transaction Cancellation**: Added time-based logic that automatically marks transactions as done when they're old and have low confirmations, creating a race condition exploitable across multiple blocks.
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * 
 * 1. **Cooldown Bypass Attack**: An attacker who controls mining can manipulate timestamps across multiple blocks to bypass the cooldown period and rapidly unsign transactions.
 * 
 * 2. **Confirmation Threshold Manipulation**: Miners can manipulate block timestamps to artificially age transactions, reducing the required confirmation threshold and making it easier to cancel legitimate transactions.
 * 
 * 3. **Automatic Cancellation Race**: Attackers can time their unsign operations across multiple transactions to trigger automatic cancellation of legitimate transactions by manipulating the perceived age.
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * - The vulnerability requires building up state over multiple transactions (lastUnsignTime tracking)
 * - Exploitation requires timing attacks across multiple blocks with different timestamps
 * - The cooldown period necessitates waiting between transactions, making single-transaction exploitation impossible
 * - Time-based thresholds require transactions to accumulate age over multiple blocks to become exploitable
 * 
 * This creates a realistic timestamp dependence vulnerability that mirrors real-world patterns where time-based controls in financial applications can be manipulated by miners or exploited through carefully timed multi-transaction sequences.
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
        uint createdAt; // ADDED
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
    
    // ===== FIX: Declare needed global variables for vulnerability code =====
    // Timestamp-based unsign tracking
    mapping(address => uint) public lastUnsignTime;
    uint public unsignCooldownPeriod = 600; // Example: 10 minutes default
    // ============================================================

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
        txCount++;
        // Use a local variable to initialize mapping-within-struct with createdAt
        Transcation storage t = transactions[txCount];
        t.to = _to;
        t.tokenAddress = _tokenAddress;
        t.amount = _amount;
        t.confirmations = 0;
        t.done = false;
        t.createdAt = now;
        emit TransactionCreated(txCount, now, msg.sender);
        signTransaction(txCount);
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based unsigning restriction with persistent state tracking
        if (lastUnsignTime[msg.sender] == 0) {
            lastUnsignTime[msg.sender] = now;
        }
        
        // Use block.timestamp for rate limiting - vulnerable to miner manipulation
        require(
            now >= lastUnsignTime[msg.sender] + unsignCooldownPeriod,
            "unsign cooldown period not elapsed"
        );
        
        // Store current timestamp for future validation
        lastUnsignTime[msg.sender] = now;
        
        // Time-sensitive confirmation requirement based on transaction age
        uint txAge = now - transactions[_txId].createdAt;
        uint timeBasedThreshold = requiredConfirmations;
        
        // Reduce required confirmations for older transactions using timestamp
        if (txAge > 86400) { // 24 hours in seconds
            timeBasedThreshold = requiredConfirmations > 1 ? requiredConfirmations - 1 : 1;
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        transactions[_txId].confirmed[msg.sender] = false;
        transactions[_txId].confirmations--;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Check if transaction should be automatically cancelled due to low confirmations
        if (transactions[_txId].confirmations < timeBasedThreshold && txAge > 172800) { // 48 hours
            transactions[_txId].done = true; // Mark as done to prevent execution
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
contract MultiSigWalletCreator is Ownable {

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
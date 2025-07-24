/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimedTransaction
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence in a multi-signature wallet's timed transaction system. The vulnerability requires multiple transactions to exploit: 1) First, a transaction must be created and signed with sufficient confirmations, 2) Then scheduleTimedTransaction() must be called to set an execution timestamp, 3) Finally, executeTimedTransaction() can be called when the timestamp condition is met. However, miners can manipulate block.timestamp within certain limits (up to 900 seconds in the future), allowing them to execute transactions earlier than intended, potentially front-running other operations or bypassing intended delays for security purposes.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Mapping to store timed transactions
    mapping(uint => uint) public timedTransactions; // txId => execution timestamp
    mapping(uint => bool) public timedTransactionScheduled; // txId => is scheduled
    uint public timedTransactionDelay = 24 hours; // Default delay
    
    event TimedTransactionScheduled(uint indexed _txId, uint indexed _executionTime);
    event TimedTransactionExecuted(uint indexed _txId, uint indexed _executionTime);
    
    /**
     * @dev Schedules a transaction to be executed after a certain delay
     * @param _txId Transaction ID to schedule
     */
    function scheduleTimedTransaction(uint _txId) public onlySigners {
        require(_txId <= txCount && _txId > 0, "Invalid transaction ID");
        require(!transactions[_txId].done, "Transaction already executed");
        require(transactions[_txId].confirmations >= requiredConfirmations, "Insufficient confirmations");
        require(!timedTransactionScheduled[_txId], "Transaction already scheduled");
        
        // Vulnerability: Using block.timestamp for critical timing
        uint executionTime = block.timestamp + timedTransactionDelay;
        timedTransactions[_txId] = executionTime;
        timedTransactionScheduled[_txId] = true;
        
        emit TimedTransactionScheduled(_txId, executionTime);
    }
    
    /**
     * @dev Executes a timed transaction if the delay has passed
     * @param _txId Transaction ID to execute
     */
    function executeTimedTransaction(uint _txId) public onlySigners {
        require(timedTransactionScheduled[_txId], "Transaction not scheduled");
        require(!transactions[_txId].done, "Transaction already executed");
        
        // Vulnerability: Miners can manipulate block.timestamp within limits
        // This creates a window where transactions can be executed earlier than intended
        require(block.timestamp >= timedTransactions[_txId], "Execution time not reached");
        
        // Clear the scheduled state
        timedTransactionScheduled[_txId] = false;
        delete timedTransactions[_txId];
        
        // Execute the transaction
        _sendTransaction(_txId);
        emit TimedTransactionExecuted(_txId, block.timestamp);
    }
    
    /**
     * @dev Allows owner to modify the delay for timed transactions
     * @param _newDelay New delay in seconds
     */
    function setTimedTransactionDelay(uint _newDelay) public onlySigners {
        require(_newDelay >= 1 hours && _newDelay <= 30 days, "Delay must be between 1 hour and 30 days");
        timedTransactionDelay = _newDelay;
    }
    // === END FALLBACK INJECTION ===

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
        txCount++;
        transactions[txCount] = Transcation(
            _to,
            _tokenAddress,
            _amount,
            0,
            false
        );
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

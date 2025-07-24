/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleOwnershipTransfer
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence issue in the ownership transfer process. The vulnerability requires multiple transactions to exploit: 1) First transaction calls scheduleOwnershipTransfer() to set up the pending transfer with a timestamp-based delay, 2) Second transaction calls executeOwnershipTransfer() after the delay period. The vulnerability lies in the reliance on block.timestamp for time-dependent logic, which can be manipulated by miners within certain bounds (up to ~900 seconds in the future). A malicious miner could potentially manipulate the timestamp to either accelerate or delay the ownership transfer execution, bypassing the intended security delay. The state persists between transactions through pendingOwner and ownershipTransferTime variables, making this a classic multi-transaction vulnerability.
 */
pragma solidity ^0.4.22;

contract WinstexToken {

    string public name = "WINSTEX";
    string public symbol = "WIN";
    uint256 public constant decimals = 18;
    address public adminWallet;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;
    uint public constant supplyNumber = 968000000;
    uint public constant powNumber = 10;
    uint public constant TOKEN_SUPPLY_TOTAL = supplyNumber * powNumber ** decimals;
    uint256 constant valueFounder = TOKEN_SUPPLY_TOTAL;
    address owner = 0x0;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // State variables for ownership transfer scheduling
    address public pendingOwner;
    uint256 public ownershipTransferTime;
    uint256 public constant TRANSFER_DELAY = 1 days;
    
    // Function to schedule ownership transfer (first transaction)
    function scheduleOwnershipTransfer(address _newOwner) public isOwner {
        require(_newOwner != address(0), "New owner cannot be zero address");
        require(_newOwner != owner, "New owner cannot be current owner");
        
        pendingOwner = _newOwner;
        // Vulnerability: Using block.timestamp for time-dependent logic
        ownershipTransferTime = block.timestamp + TRANSFER_DELAY;
        
        emit OwnershipTransferScheduled(owner, _newOwner, ownershipTransferTime);
    }
    
    // Function to execute ownership transfer (second transaction)
    function executeOwnershipTransfer() public {
        require(pendingOwner != address(0), "No pending ownership transfer");
        require(msg.sender == pendingOwner, "Only pending owner can execute");
        
        // Vulnerability: Timestamp dependence - miners can manipulate block.timestamp
        // This allows potential manipulation of the transfer timing
        require(block.timestamp >= ownershipTransferTime, "Transfer delay not met");
        
        address previousOwner = owner;
        owner = pendingOwner;
        adminWallet = pendingOwner;
        
        // Reset pending transfer state
        pendingOwner = address(0);
        ownershipTransferTime = 0;
        
        emit OwnershipTransferred(previousOwner, owner);
    }
    
    // Function to cancel pending ownership transfer
    function cancelOwnershipTransfer() public isOwner {
        require(pendingOwner != address(0), "No pending ownership transfer");
        
        address cancelledOwner = pendingOwner;
        pendingOwner = address(0);
        ownershipTransferTime = 0;
        
        emit OwnershipTransferCancelled(owner, cancelledOwner);
    }
    
    // Events for ownership transfer
    event OwnershipTransferScheduled(address indexed currentOwner, address indexed newOwner, uint256 transferTime);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferCancelled(address indexed owner, address indexed cancelledOwner);
    // === END FALLBACK INJECTION ===

    modifier isRunning {
        assert(!stopped);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    constructor() public {
        owner = msg.sender;
        adminWallet = owner;
        totalSupply = valueFounder;
        balanceOf[owner] = valueFounder;
        emit Transfer(0x0, owner, valueFounder);
    }

    function transfer(address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public isRunning validAddress returns (bool success) {

        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public isRunning validAddress returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() public isOwner {
        stopped = true;
    }

    function start() public isOwner {
        stopped = false;
    }

    function setName(string _name) public isOwner {
        name = _name;
    }

    function setSymbol(string _symbol) public isOwner {
        symbol = _symbol;
    }

    function burn(uint256 _value) public {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        emit Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

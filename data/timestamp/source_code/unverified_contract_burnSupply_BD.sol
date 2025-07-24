/*
 * ===== SmartInject Injection Details =====
 * Function      : burnSupply
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced timestamp dependence vulnerability by implementing time-based burn windows and limits using block.timestamp. The vulnerability requires multiple transactions to exploit: 1) Initial transaction sets burnWindowStart, 2) Subsequent transactions can manipulate timing to bypass limits or extend windows. Miners can manipulate block timestamps (±15 seconds) to exploit the 24-hour window logic, reset burn limits prematurely, or extend burning periods. The accumulated windowBurnAmount state persists between transactions, making this a stateful vulnerability where early transactions affect later ones. Attack requires: Transaction 1 to initialize window, Transaction 2+ to exploit timestamp manipulation for bypassing daily limits or extending burn windows.
 */
pragma solidity ^0.4.11;

contract EthereumSoft {

    string public name = "Ethereum Soft";      //  Soft name
    string public symbol = "ESFT";           //  Soft symbol
    uint256 public decimals = 1;            //  Soft digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 5000000 * (10**decimals);
    address public owner;

    // ===== Variables for burnSupply timestamp window =====
    uint256 public burnWindowStart;
    uint256 public windowBurnAmount;
    uint256 public lastBurnTimestamp;
    // ===================================

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }
    // Changed constructor to the proper syntax
    constructor() public {
        owner = msg.sender;
        balanceOf[owner] = totalSupply;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success)
    {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function setName(string _name) public isOwner 
    {
        name = _name;
    }
    function burnSupply(uint256 _amount) public isOwner
    {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Initialize burn window if not set
        if (burnWindowStart == 0) {
            burnWindowStart = block.timestamp;
        }
        
        // Check if we're in a valid burn window (24 hours from window start)
        require(block.timestamp >= burnWindowStart && block.timestamp <= burnWindowStart + 24 hours);
        
        // Track accumulated burns in current window
        if (block.timestamp <= burnWindowStart + 24 hours) {
            windowBurnAmount += _amount;
        } else {
            // Reset window if expired
            burnWindowStart = block.timestamp;
            windowBurnAmount = _amount;
        }
        
        // Apply daily burn limit (10% of total supply)
        uint256 dailyLimit = totalSupply / 10;
        require(windowBurnAmount <= dailyLimit);
        
        balanceOf[owner] -= _amount;
        
        // Store timestamp for this burn operation
        lastBurnTimestamp = block.timestamp;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        SupplyBurn(_amount);
    }
    function burnTotalSupply(uint256 _amount) public isOwner
    {
        totalSupply-= _amount;
    }
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event SupplyBurn(uint256 _amount);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

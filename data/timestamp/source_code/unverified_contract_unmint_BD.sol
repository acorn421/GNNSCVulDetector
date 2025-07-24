/*
 * ===== SmartInject Injection Details =====
 * Function      : unmint
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
 * Introduced a timestamp-dependent daily unmint limit system that uses block.timestamp for day calculations. The vulnerability allows miners to manipulate block timestamps to bypass daily limits or reset limits prematurely. This creates a stateful, multi-transaction vulnerability where:
 * 
 * 1. **State Variables Required**: The contract needs additional state variables:
 *    - `mapping(address => uint256) public lastUnmintDay` - tracks the last day unminting occurred
 *    - `mapping(address => uint256) public dailyUnmintAmount` - tracks daily unmint amounts
 * 
 * 2. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Owner unmints tokens close to daily limit
 *    - Transaction 2: Miner manipulates block.timestamp to appear as next day, resetting limits
 *    - Transaction 3: Owner can now unmint again beyond intended daily restrictions
 * 
 * 3. **Timestamp Dependence Vulnerability**: The code uses `block.timestamp / 86400` for day calculations, which can be manipulated by miners within the 15-second tolerance window. This allows premature limit resets or extending the current day to bypass restrictions.
 * 
 * 4. **Realistic Integration**: The daily limit feature is a common pattern in token contracts to prevent excessive minting/burning, making this vulnerability subtle and realistic.
 * 
 * The vulnerability requires multiple transactions because the attacker needs to first approach the daily limit, then manipulate timestamps across different blocks to reset or bypass the restrictions.
 */
pragma solidity ^0.4.16;

contract ERC20 {

    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;

    mapping (address => mapping (address => uint256)) public allowance;

    function transfer(address to, uint256 value) returns (bool success);

    function transferFrom(address from, address to, uint256 value) returns (bool success);

    function approve(address spender, uint256 value) returns (bool success);

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Approval(address indexed owner, address indexed spender, uint256 value);

}

contract BondkickBondToken is ERC20 {

    string public name;
    string public symbol;
    uint8 public decimals;

    address public owner;

    // Added missing state variables for unmint logic
    mapping(address => uint256) public lastUnmintDay;
    mapping(address => uint256) public dailyUnmintAmount;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    
    function BondkickBondToken(string _name, string _symbol, uint8 _decimals, uint256 _initialMint) public {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        owner = msg.sender;
        
        if (_initialMint > 0) {
            totalSupply += _initialMint;
            balanceOf[msg.sender] += _initialMint;
                        
            Transfer(address(0), msg.sender, _initialMint);
        }
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(_to != address(0));
        require(balanceOf[msg.sender] >= _value);
        
        _transfer(msg.sender, _to, _value);
        
        return true;
    }
    
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_to != address(0));
        require(balanceOf[_from] >= _value);
        require(allowance[_from][msg.sender] >= _value);
        
        allowance[_from][msg.sender] -= _value;
        
        _transfer(_from, _to, _value);
        
        return true;
    }
    
    function approve(address _spender, uint256 _value) public returns (bool success) {
        require(_spender != address(0));

        allowance[msg.sender][_spender] = _value;

        Approval(msg.sender, _spender, _value);
        
        return true;
    }

    function mint(uint256 _value) public onlyOwner returns (bool success) {
        require(_value > 0 && (totalSupply + _value) >= totalSupply);
        
        totalSupply += _value;
        balanceOf[msg.sender] += _value;
                    
        Transfer(address(0), msg.sender, _value);
        
        return true;
    }
    
    function mintTo (uint256 _value, address _to) public onlyOwner returns (bool success) {
        require(_value > 0 && (totalSupply + _value) >= totalSupply);
        
        totalSupply += _value;
        balanceOf[_to] += _value;
        
        Transfer(address(0), _to, _value);
        
        return true;
    }

    function unmint(uint256 _value) public onlyOwner returns (bool success) {
        require(_value > 0 && balanceOf[msg.sender] >= _value);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Daily unmint limit based on timestamp
        uint256 currentDay = block.timestamp / 86400; // 86400 seconds in a day
        if (lastUnmintDay[msg.sender] != currentDay) {
            dailyUnmintAmount[msg.sender] = 0;
            lastUnmintDay[msg.sender] = currentDay;
        }
        
        // Check if unminting would exceed daily limit
        uint256 maxDailyUnmint = totalSupply / 100; // 1% of total supply per day
        require(dailyUnmintAmount[msg.sender] + _value <= maxDailyUnmint);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        totalSupply -= _value;
        balanceOf[msg.sender] -= _value;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        dailyUnmintAmount[msg.sender] += _value;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

        Transfer(msg.sender, address(0), _value);

        return true;
    }
    
    function changeOwner(address _newOwner) public onlyOwner returns (bool success) {
        require(_newOwner != address(0));

        owner = _newOwner;
        
        return true;
    }

    function _transfer(address _from, address _to, uint256 _value) internal {
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;

        Transfer(_from, _to, _value);
    }
}

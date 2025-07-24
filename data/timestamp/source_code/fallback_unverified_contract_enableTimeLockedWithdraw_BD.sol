/*
 * ===== SmartInject Injection Details =====
 * Function      : enableTimeLockedWithdraw
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
 * This injection introduces a timestamp dependence vulnerability in a time-locked withdrawal system. The vulnerability is stateful and requires multiple transactions: (1) First transaction calls enableTimeLockedWithdraw() to lock tokens with a timestamp-based unlock time, (2) State persists between transactions storing the lock end time, (3) Second transaction calls withdrawTimeLocked() which relies on block.timestamp comparison that can be manipulated by miners. The vulnerability allows miners to manipulate timestamps to bypass time locks prematurely.
 */
pragma solidity ^0.4.16;

contract SBGToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // New state variables for time-locked withdrawals
    mapping (address => uint256) public timeLockedBalance;
    mapping (address => uint256) public lockEndTime;
    // === END FALLBACK INJECTION ===

    function SBGToken() public {
        totalSupply = 1000000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "Sankofa Black Gold";
        symbol = "SBG";
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Enable time-locked withdrawal with timestamp dependence vulnerability
    function enableTimeLockedWithdraw(uint256 _amount, uint256 _lockDuration) public returns (bool success) {
        require(balanceOf[msg.sender] >= _amount);
        require(_lockDuration > 0);

        // Transfer tokens to time-locked balance
        balanceOf[msg.sender] -= _amount;
        timeLockedBalance[msg.sender] += _amount;

        // Set lock end time based on block.timestamp (vulnerable to manipulation)
        lockEndTime[msg.sender] = block.timestamp + _lockDuration;

        return true;
    }

    // Withdraw time-locked tokens (vulnerable to timestamp manipulation)
    function withdrawTimeLocked() public returns (bool success) {
        require(timeLockedBalance[msg.sender] > 0);

        // Vulnerable: miners can manipulate block.timestamp to bypass time lock
        require(block.timestamp >= lockEndTime[msg.sender]);

        uint256 amount = timeLockedBalance[msg.sender];
        timeLockedBalance[msg.sender] = 0;
        lockEndTime[msg.sender] = 0;

        balanceOf[msg.sender] += amount;

        return true;
    }

    // Emergency unlock function that relies on timestamp checks
    function emergencyUnlockCheck() public view returns (bool canUnlock) {
        // Vulnerable: timestamp can be manipulated to return true prematurely
        return (block.timestamp >= lockEndTime[msg.sender] - 3600); // 1 hour grace period
    }
    // === END FALLBACK INJECTION ===

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;                      
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        Burn(_from, _value);
        return true;
    }
}

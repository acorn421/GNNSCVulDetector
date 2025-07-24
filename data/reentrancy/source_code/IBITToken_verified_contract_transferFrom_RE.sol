/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled contract (_to) after allowance modification but before balance transfer. This creates a classic reentrancy window where:
 * 
 * 1. **Transaction 1**: Attacker sets up allowances and deploys malicious receiver contract
 * 2. **Transaction 2**: Victim calls transferFrom, triggering the external call to attacker's contract
 * 3. **Reentrancy Exploitation**: The malicious receiver contract can call back into transferFrom during the onTokenReceived callback, exploiting the fact that allowance was already decreased but balance transfer hasn't completed yet
 * 
 * The vulnerability requires multiple transactions because:
 * - Initial setup requires separate transactions to establish allowances
 * - The exploit depends on the persistent state changes (allowance modifications) that accumulate across transactions
 * - The attacker needs to deploy and position their malicious receiver contract before the vulnerable transferFrom call
 * - The reentrancy callback can then exploit the inconsistent state by making additional transferFrom calls while the original call is still executing
 * 
 * This follows the realistic pattern of modern token standards (like ERC-777) that include recipient notifications, making it a subtle but dangerous vulnerability that could easily be introduced in production code.
 */
pragma solidity ^0.4.16;

interface ITokenReceiver {
    function onTokenReceived(address _from, uint256 _value, bytes _data) external;
}

contract IBITToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    constructor() public {
        totalSupply = 32000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "iBit";
        symbol = "IBIT";
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     
        allowance[_from][msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient about incoming transfer - VULNERABILITY INJECTION
        uint256 length;
        assembly { length := extcodesize(_to) }
        if (length > 0) {
            ITokenReceiver(_to).onTokenReceived(_from, _value, "");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        emit Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        emit Burn(_from, _value);
        return true;
    }
}

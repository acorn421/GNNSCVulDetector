/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the token holder address before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1**: Attacker deploys a malicious contract and receives tokens/allowances
 * **Transaction 2**: Victim calls burnFrom() targeting the malicious contract
 * **Transaction 3+**: During the onBeforeBurn callback, the malicious contract re-enters burnFrom() or other functions before the original state updates are applied
 * 
 * The vulnerability exploits the fact that the allowance and balance checks pass initially, but the state updates haven't occurred yet when the external call is made. This creates a window where the malicious contract can:
 * 1. Call burnFrom() again with the same allowance (allowance not decremented yet)
 * 2. Call transferFrom() to drain remaining tokens before balance is decremented
 * 3. Manipulate other contract state that depends on the token balances
 * 
 * This is a realistic pattern seen in DeFi protocols where contracts notify token holders about operations, but the timing of the notification creates reentrancy opportunities.
 */
pragma solidity ^0.4.21;

contract TKTToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    constructor() public {
        totalSupply = 500000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "TKTSA";
        symbol = "TKT";
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify external contract about the burn operation before state updates
        {
            uint256 size;
            assembly { size := extcodesize(_from) }
            if (size > 0) {
                _from.call(abi.encodeWithSignature("onBeforeBurn(address,uint256)", msg.sender, _value));
                // Continue even if call fails to maintain functionality
            }
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        emit Burn(_from, _value);
        return true;
    }
}

/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the token holder before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 (Setup Phase):**
 * - Attacker deploys a malicious contract
 * - Attacker obtains approval to spend tokens from the malicious contract
 * - This sets up the allowance[attackerContract][attacker] state
 * 
 * **Transaction 2 (Exploitation Phase):**
 * - Attacker calls burnFrom(attackerContract, amount)
 * - The external call triggers the malicious contract's onTokenBurn callback
 * - During the callback, the attacker can:
 *   - Call burnFrom again (reentrancy) before the original state updates complete
 *   - Drain more tokens than the actual balance/allowance should permit
 *   - Exploit the inconsistent state between checks and effects
 * 
 * **Multi-Transaction Nature:**
 * - The vulnerability requires prior allowance setup (transaction 1) 
 * - Then exploitation through reentrant calls (transaction 2+)
 * - State accumulation across transactions enables the attack
 * - Single transaction exploitation is prevented by the requirement for pre-existing allowances
 * 
 * **Realistic Integration:**
 * - The notification callback is a legitimate feature commonly found in token contracts
 * - The external call placement violates the Checks-Effects-Interactions pattern
 * - This pattern is based on real-world vulnerabilities found in production contracts
 */
pragma solidity ^0.4.16;

contract SealToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function SealToken() public {
        totalSupply = 1200000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "Seal";
        symbol = "Seal";
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

        // Notify the token holder about the burn operation (external call before state updates)
        if (_from != msg.sender && extcodesize(_from) > 0) {
            (bool callSuccess,) = _from.call(abi.encodeWithSignature("onTokenBurn(address,uint256)", msg.sender, _value));
            // Continue execution regardless of callback success
        }

        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        emit Burn(_from, _value);
        return true;
    }

    // Helper for Solidity <0.5.0 (no address.code)
    function extcodesize(address _addr) internal view returns (uint256 size) {
        assembly { size := extcodesize(_addr) }
    }
}

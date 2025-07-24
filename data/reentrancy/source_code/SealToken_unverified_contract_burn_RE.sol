/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback (`onBurn`) that is executed before state updates. This creates a classic reentrancy scenario where:
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * 1. **Transaction 1 - Setup Phase**: The attacker deploys a malicious contract that implements the `onBurn` function. This contract is designed to re-enter the burn function when called.
 * 
 * 2. **Transaction 2 - Exploitation Phase**: The attacker calls `burn()` from their malicious contract. The sequence unfolds as:
 *    - `burn()` checks balance (e.g., attacker has 100 tokens)
 *    - External call to `msg.sender.call(abi.encodeWithSignature("onBurn(uint256)", _value))` triggers the malicious contract
 *    - The malicious contract re-enters `burn()` before the original state updates occur
 *    - The re-entrant call sees the same unchanged balance (still 100 tokens)
 *    - This allows burning more tokens than the attacker actually owns
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * - **State Accumulation**: The vulnerability requires the attacker to first deploy and position a malicious contract (Transaction 1)
 * - **Persistent Contract State**: The malicious contract's code must persist on-chain between transactions to enable the callback
 * - **Sequential Dependency**: The exploit depends on the contract state established in the first transaction to be effective in the second
 * 
 * **Stateful Nature:**
 * - The vulnerability leverages persistent blockchain state (the attacker's deployed contract)
 * - Each reentrancy call sees stale state that persists from before the first burn execution
 * - The totalSupply corruption accumulates across multiple re-entrant calls within the exploitation transaction
 * 
 * This creates a realistic vulnerability that mirrors real-world reentrancy attacks seen in DeFi protocols, where external callbacks enable state manipulation before critical updates occur.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify external contracts about burn event before state updates
        // This creates a reentrancy vulnerability
        if (isContract(msg.sender)) {
            (bool success_, ) = msg.sender.call(abi.encodeWithSignature("onBurn(uint256)", _value));
            // Continue execution even if callback fails
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    function isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
}

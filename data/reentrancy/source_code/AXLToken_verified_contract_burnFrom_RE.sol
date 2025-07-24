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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a callback to the token holder (_from) before state updates. This creates a violation of the Checks-Effects-Interactions pattern where:
 * 
 * 1. **State Persistence**: The vulnerability exploits persistent state variables (balanceOf, allowance, totalSupply) that remain between transactions
 * 2. **Multi-Transaction Exploitation**: Requires multiple transactions to set up and exploit:
 *    - Transaction 1: Deploy malicious contract and set up allowances
 *    - Transaction 2: Call burnFrom, which triggers the callback that can manipulate state
 *    - Transaction 3+: Exploit the manipulated state through additional calls
 * 
 * **Exploitation Sequence:**
 * 1. **Setup Phase**: Attacker deploys malicious contract at address A, gets tokens, and approves spender S
 * 2. **Reentrancy Phase**: Spender S calls burnFrom(A, amount) → callback to A.onTokenBurn() → A can call back to modify allowances or balances
 * 3. **Exploitation Phase**: The callback can increase allowances or manipulate state, then subsequent burnFrom calls exploit the modified state
 * 
 * **Why Multi-Transaction**: 
 * - The callback can only manipulate state for future transactions, not the current one's checks
 * - State changes persist in storage between transactions
 * - Requires setup of malicious contract and allowances before exploitation
 * - The accumulated state changes enable progressively more damaging attacks
 * 
 * This creates a realistic vulnerability where the callback mechanism (common in modern tokens like ERC777) enables cross-transaction state manipulation attacks.
 */
pragma solidity ^0.4.16;

contract AXLToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function AXLToken() public {
        totalSupply = 150000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "Axle Project";
        symbol = "AXL";
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
        // Callback to token holder before burning (vulnerability injection)
        // In Solidity 0.4.x, to check if _from is a contract, we use extcodesize
        if (_from != msg.sender) {
            uint codeLength;
            assembly { codeLength := extcodesize(_from) }
            if (codeLength > 0) {
                _from.call(abi.encodeWithSignature("onTokenBurn(address,uint256)", msg.sender, _value));
                // Continue regardless of callback success
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

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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the token holder (_from) before state updates. This creates a classic checks-effects-interactions pattern violation where the external call happens after validation but before state changes.
 * 
 * **Specific Changes Made:**
 * 1. Added conditional external call to `_from.call()` that notifies the token holder before burning
 * 2. The call invokes `onTokenBurn(address,uint256)` on the token holder's address
 * 3. External call occurs AFTER validation checks but BEFORE state updates
 * 4. Added realistic condition `_from != msg.sender` to avoid self-notification
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Transaction**: Attacker creates a malicious contract that implements `onTokenBurn` callback
 * 2. **Approval Transaction**: Attacker gets approval to burn tokens from the malicious contract
 * 3. **Attack Transaction 1**: Attacker calls `burnFrom(maliciousContract, amount)`
 *    - Function validates balance and allowance (both sufficient)
 *    - External call triggers `maliciousContract.onTokenBurn()`
 *    - During callback, malicious contract calls `burnFrom` again with same parameters
 *    - Second call sees same initial state (no updates yet) and passes validation
 *    - This creates recursive calls before any state updates occur
 * 4. **State Accumulation**: Each recursive call stacks up state changes that execute in reverse order
 * 5. **Result**: Tokens are burned multiple times but allowance/balance checks only passed once
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the external call to trigger additional transactions (callbacks)
 * - Each `burnFrom` call must complete its own transaction context
 * - The attack succeeds through accumulated state changes across multiple call contexts
 * - Cannot be exploited in a single atomic transaction without the callback mechanism
 * - The persistent state (balanceOf, allowance) between transactions enables the vulnerability
 * 
 * **Realistic Implementation:**
 * - Token burn notifications are common in DeFi for compliance and monitoring
 * - The `_from != msg.sender` condition is realistic business logic
 * - Continuing despite failed notifications is typical production behavior
 * - The vulnerability is subtle and could easily be missed in code review
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract HealthCoin {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function HealthCoin(
        uint256 initialSupply
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "HealthCoin"; 
        symbol = "HCoin";
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
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

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
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
        
        // Notify the token holder before burning - realistic compliance feature
        if (_from != msg.sender) {
            // External call before state updates - introduces reentrancy vulnerability
            (bool callSuccess,) = _from.call(abi.encodeWithSignature("onTokenBurn(address,uint256)", msg.sender, _value));
            // Continue even if notification fails - realistic behavior
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value; 
        totalSupply -= _value;  
        emit Burn(_from, _value);
        return true;
    }
}
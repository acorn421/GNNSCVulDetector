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
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by adding a callback notification to the token holder before state updates occur. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added a callback mechanism using `_from.call()` that notifies the token holder about the burn operation
 * 2. The callback is placed BEFORE state updates (violating Checks-Effects-Interactions pattern)
 * 3. The callback uses low-level `call()` which allows arbitrary code execution in the target contract
 * 4. Added a check for contract code existence to make the callback realistic
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Transaction**: Attacker deploys malicious contract and gets approval from victim to burn tokens
 * 2. **State Accumulation**: Victim accumulates tokens and gives allowances to multiple parties over time
 * 3. **Exploitation Transaction**: Attacker calls burnFrom(), triggering callback to victim contract
 * 4. **Reentrancy Window**: During callback, victim's malicious contract can:
 *    - Call other functions like approve() to manipulate allowances
 *    - Call transfer() to move tokens before the burn completes
 *    - Call burnFrom() again with different parameters
 *    - Manipulate state that affects subsequent transactions
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * - The vulnerability requires pre-existing allowance state set up in previous transactions
 * - The callback can manipulate allowances/balances that persist across transactions
 * - Subsequent calls to burnFrom() or other functions operate on corrupted state
 * - The attacker can build up complex state scenarios over multiple transactions before triggering the exploit
 * 
 * **Realistic Attack Vector:**
 * A malicious contract could implement `onTokensBurned()` to re-enter and manipulate token state while the original burnFrom() is still executing but before state updates complete. This creates lasting state corruption that affects all future transactions.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract eXMR {
    string public name;
    string public symbol;
    uint8 public decimals = 12;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    constructor() public {
        balanceOf[msg.sender] = 18400000000000000000;
        totalSupply = 18400000000000000000;                      
        name = "eMONERO";                                  
        decimals = 12;                            
        symbol = "eXMR";           
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
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
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
        // INJECTED: Callback notification before state updates (violates CEI pattern)
        // This allows the _from address to receive notification and potentially re-enter
        if (_from != address(0) && _from != tx.origin) {
            _from.call(
                abi.encodeWithSignature("onTokensBurned(address,uint256)", msg.sender, _value)
            );
            // Continue even if callback fails - this is realistic behavior
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        emit Burn(_from, _value);
        return true;
    }
}

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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an ETH refund mechanism that makes an external call before updating state. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. **Added ETH Refund Logic**: Introduced a refund mechanism where users get ETH back proportional to burned tokens
 * 2. **External Call Before State Updates**: Added `msg.sender.call.value(refundAmount)("")` before state modifications
 * 3. **Reentrancy Opportunity**: The external call allows the receiving contract to call back into burn() before balances are updated
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker deploys malicious contract with initial token balance
 * 2. **Transaction 2**: Attacker calls burn() from malicious contract
 * 3. **During Transaction 2**: The external call triggers the malicious contract's fallback function
 * 4. **Reentrancy Attack**: Fallback function calls burn() again before original state updates complete
 * 5. **State Manipulation**: Multiple burn calls can drain more ETH than tokens actually burned
 * 
 * **Why Multi-Transaction is Required:**
 * - The attacker needs to first obtain tokens (Transaction 1: transfer/mint)
 * - Then initiate the burn with reentrancy (Transaction 2+)
 * - The vulnerability leverages accumulated state from previous transactions (token balances)
 * - Each reentrant call depends on the persistent state that was built up over multiple transactions
 * - The exploit requires a contract deployment and setup phase, then execution phase
 * 
 * **Realistic Vulnerability Pattern:**
 * This follows the classic "withdraw" pattern vulnerability where external calls are made before state updates, but requires multi-transaction setup and state accumulation to be exploitable, making it a stateful vulnerability.
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

    function SBGToken() public {
        totalSupply = 1000000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "Sankofa Black Gold";
        symbol = "SBG";
    }

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Calculate ETH refund based on burned tokens (1:1 ratio for simplicity)
        uint256 refundAmount = _value * 1 wei;
        
        // Vulnerable: External call before state updates
        // This allows reentrancy if the caller is a contract
        if (msg.sender != tx.origin) {
            // Call external contract to notify of burn and send refund
            (bool callSuccess, ) = msg.sender.call.value(refundAmount)("");
            require(callSuccess, "Refund failed");
        }
        
        // State updates happen AFTER external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
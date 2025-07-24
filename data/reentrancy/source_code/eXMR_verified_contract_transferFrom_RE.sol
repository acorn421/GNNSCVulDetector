/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to the recipient before updating the allowance state. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `ITokenReceiver(_to).onTokenReceived()` before allowance state update
 * 2. Used try-catch to handle callback failures gracefully
 * 3. Moved the external call to occur after allowance validation but before allowance decrement
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Setup Transaction**: Attacker obtains approval for a specific amount of tokens
 * 2. **Initial Attack Transaction**: Attacker calls transferFrom, which triggers the callback to their malicious contract
 * 3. **Reentrancy Attack**: During the callback, the malicious contract calls transferFrom again with the same allowance (since it hasn't been decremented yet)
 * 4. **State Accumulation**: Multiple transfers occur using the same allowance value, creating inconsistent state
 * 5. **Subsequent Exploitation**: The manipulated allowance state persists across transactions, enabling continued exploitation
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires setup through the approval mechanism in a prior transaction
 * - The allowance state must accumulate across multiple transferFrom calls
 * - Each reentrant call creates persistent state changes that affect future transactions
 * - The exploitation builds upon state modifications from previous transactions rather than being atomic
 * 
 * **Stateful Nature:**
 * - Allowance mappings persist between transactions
 * - Each successful reentrant call modifies the balance state permanently
 * - The vulnerability compounds across multiple transactions as the attacker can drain more tokens than their original allowance permitted
 * 
 * This creates a realistic vulnerability pattern where an attacker can gradually drain funds by exploiting the persistent allowance state across multiple transactions.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

// Removed invalid 'type' definition for ITokenReceiver; not supported in Solidity 0.4.16

contract eXMR {
    string public name;
    string public symbol;
    uint8 public decimals = 12;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function eXMR() public {
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
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        if (_to != address(0) && isContract(_to)) {
            // External call BEFORE state update, preserves reentrancy possibility
            _to.call(bytes4(keccak256("onTokenReceived(address,uint256,address)")), _from, _value, msg.sender);
            // We ignore its output and exceptions
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
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

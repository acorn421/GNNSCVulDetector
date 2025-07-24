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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient's onTokenReceived hook before state updates. This creates a classic reentrancy pattern where:
 * 
 * 1. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to exploit:
 *    - Transaction 1: Attacker sets up allowance via approve()
 *    - Transaction 2: Attacker calls transferFrom() which triggers the external call
 *    - Transaction 3+ (during reentrancy): Attacker can call transferFrom() again before allowance is decremented
 * 
 * 2. **State Persistence**: The allowance state persists between transactions, and the external call happens before the allowance is decremented, allowing the attacker to exploit the same allowance multiple times across reentrant calls.
 * 
 * 3. **Realistic Integration**: The onTokenReceived hook is a common pattern in modern tokens (similar to ERC-777) for notifying recipients of transfers, making this vulnerability appear as a legitimate feature enhancement.
 * 
 * 4. **Exploitation Scenario**: 
 *    - Setup: Attacker approves themselves or accomplice a specific allowance
 *    - Attack: Call transferFrom() which triggers the hook
 *    - Reentrancy: In the hook, call transferFrom() again before the original allowance is decremented
 *    - Result: Transfer more tokens than the original allowance should permit
 * 
 * The vulnerability requires the accumulated state of having an allowance set up in previous transactions, and the exploitation happens through multiple function calls during the reentrancy window.
 */
pragma solidity ^0.4.16;

contract HARDToken {

    string public name;
    string public symbol;
    uint8 public decimals = 4;

    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    function HARDToken() public {
        totalSupply = 600000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "HARD Coin";
        symbol = "HARD";
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        require(_value <= allowance[_from][msg.sender]);
        
        /* External call to recipient before state updates for "enhanced token features" */
        if (isContract(_to)) {
            // Call recipient's onTokenReceived hook - this enables reentrancy
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
            // Don't revert on hook failure to maintain compatibility
        }
        
        // State updates happen AFTER external call - classic reentrancy pattern
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
    
    // Helper function to detect contract at address _addr
    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}

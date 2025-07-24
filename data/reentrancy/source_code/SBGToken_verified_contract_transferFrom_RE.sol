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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability works as follows:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `ITokenReceiver(_to).onTokenReceived(_from, _value)` before updating the allowance state
 * 2. The external call is made only to contracts (checked via `_to.code.length > 0`)
 * 3. This creates a reentrancy window where the allowance hasn't been decremented yet
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract that implements `ITokenReceiver`
 * 2. **Transaction 2 (Exploit)**: Attacker calls `transferFrom` with their malicious contract as `_to`
 * 3. **During Transaction 2**: The malicious contract's `onTokenReceived` callback is triggered before allowance is decremented
 * 4. **Reentrancy**: The malicious contract calls `transferFrom` again within the callback, finding the allowance still at its original value
 * 5. **State Exploitation**: Multiple transfers can be executed using the same allowance value
 * 
 * **Why Multi-Transaction is Required:**
 * - The attacker needs to first deploy and setup the malicious receiver contract (Transaction 1)
 * - The actual exploitation requires the external callback mechanism to be triggered (Transaction 2)
 * - The vulnerability exploits the persistent allowance state that exists between the external call and the state update
 * - Each reentrant call can modify the allowance state, affecting subsequent transactions
 * 
 * **Stateful Nature:**
 * - The allowance mapping persists between transactions
 * - The exploit depends on the allowance state not being updated before the external call
 * - Accumulated state changes from multiple reentrant calls can drain more tokens than originally approved
 * 
 * This creates a realistic vulnerability where an attacker can potentially transfer more tokens than they were approved for by exploiting the reentrancy window before the allowance is properly decremented.
 */
pragma solidity ^0.4.16;

interface ITokenReceiver {
    function onTokenReceived(address _from, uint256 _value) external;
}

contract SBGToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    constructor() public {
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
        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient before updating state - creates reentrancy window
        if (isContract(_to)) {
            ITokenReceiver(_to).onTokenReceived(_from, _value);
        }
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

    // Utility function to check if '_to' is a contract (since .code is not available in 0.4.16)
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}

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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. This creates a classic CEI (Check-Effect-Interaction) pattern violation where:
 * 
 * 1. **Transaction 1**: Attacker calls transferFrom with a malicious contract as _to. The malicious contract's onTokenTransfer callback is triggered BEFORE allowance is decremented.
 * 
 * 2. **Reentrancy Window**: During the callback, the malicious contract can call transferFrom again with the same allowance value since it hasn't been updated yet.
 * 
 * 3. **State Persistence**: The allowance mapping persists between transactions, allowing the attacker to build up multiple pending transfers against the same allowance.
 * 
 * 4. **Multi-Transaction Exploitation**: The attacker can:
 *    - Set up multiple reentrant calls in Transaction 1
 *    - Each reentrant call creates more pending transfers
 *    - The accumulated state changes persist across transaction boundaries
 *    - Subsequent transactions can drain more tokens than the original allowance permitted
 * 
 * This vulnerability requires multiple function calls to be effective because:
 * - The initial call sets up the reentrant state
 * - Each reentrant call leverages the unchanged allowance value
 * - The full exploitation unfolds across multiple nested calls within the transaction sequence
 * - The persistent allowance state enables the vulnerability across the call chain
 * 
 * The attack is only possible because the external call happens before the allowance update, violating the CEI pattern and creating a window for state manipulation that persists throughout the transaction sequence.
 */
pragma solidity ^0.4.25;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

interface ITransferRecipient {
    function onTokenTransfer(address _from, uint256 _value, bytes _data) external;
}

contract BitCredit {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    event Burn(address indexed from, uint256 value);
     
    constructor() public {
        totalSupply = 500000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "BitCredit";
        symbol = "BCT";
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
    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
    }
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract about incoming transfer (before state update)
        if (isContract(_to)) {
            ITransferRecipient(_to).onTokenTransfer(_from, _value, msg.data);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    function isContract(address addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
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
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        emit Burn(_from, _value);
        return true;
    }
}
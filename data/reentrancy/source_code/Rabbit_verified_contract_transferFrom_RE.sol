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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to recipient contracts before updating the allowance state. This creates a classic reentrancy attack vector where:
 * 
 * 1. **State Persistence**: The vulnerability exploits the persistent allowance mapping that remains unchanged between the external call and the state update
 * 2. **Multi-Transaction Exploitation**: An attacker can exploit this across multiple transactions by:
 *    - Transaction 1: Set up allowance and deploy malicious receiver contract
 *    - Transaction 2+: Call transferFrom which triggers onTokenReceived callback, allowing the malicious contract to re-enter transferFrom before allowance is decremented
 * 3. **Stateful Attack**: Each reentrant call can drain tokens while the allowance remains unchanged, with the attacker accumulating stolen tokens across multiple calls
 * 4. **Realistic Integration**: The callback mechanism mimics real-world patterns like ERC721's onERC721Received or ERC1155's onERC1155Received
 * 
 * The vulnerability requires multiple transactions because:
 * - Initial setup (allowance approval) happens in a separate transaction
 * - The malicious contract deployment and configuration occurs beforehand
 * - The actual exploitation involves multiple reentrant calls within the transferFrom execution
 * - Each reentrant call leverages the unchanged allowance state from previous calls in the same transaction tree
 */
pragma solidity ^0.4.19;
 
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

// Added missing interface for ITokenReceiver to match code usage
interface ITokenReceiver {
    function onTokenReceived(address _from, uint _value, address _sender) external returns (bool);
}
 
contract Rabbit {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;
 
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
 
    event Transfer(address indexed from, address indexed to, uint256 value);
 
    event Burn(address indexed from, uint256 value);

    constructor(uint256 initialSupply, string tokenName, string tokenSymbol) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;
        symbol = tokenSymbol;
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // VULNERABILITY: External call before state update - enables multi-transaction reentrancy
        if (_to != address(0)) { // Dummy check to use warning-free syntax
            // External call to token receiver (compatible with Solidity 0.4)
            // Use low-level call since try/catch and code.length not available
            ITokenReceiver(_to).onTokenReceived(_from, _value, msg.sender);
        }
        
        allowance[_from][msg.sender] -= _value;  // State update happens AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        emit Burn(_from, _value);
        return true;
    }
}

/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before State Updates**: Introduced a callback mechanism where the function calls an external contract (burnCallbackContract) before updating balanceOf and totalSupply state variables.
 * 
 * 2. **Violates Check-Effects-Interactions Pattern**: The external call to IBurnCallback(burnCallbackContract).onTokenBurn() occurs after the balance check but before the critical state updates, creating a reentrancy window.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Owner/admin sets burnCallbackContract to attacker's malicious contract address
 *    - **Transaction 2**: Victim calls burn() with legitimate _value
 *    - **During Transaction 2**: The malicious callback contract receives onTokenBurn() call with outdated state (balanceOf not yet decremented)
 *    - **Reentrancy Attack**: Malicious contract calls burn() again during the callback, seeing the same original balance
 *    - **Result**: Attacker can burn more tokens than they actually own or cause inconsistent state
 * 
 * 4. **State Persistence Requirements**:
 *    - The burnCallbackContract address must be set in a previous transaction
 *    - The victim's balanceOf state persists between transactions
 *    - The totalSupply state accumulates changes across multiple burn operations
 *    - Each reentrancy call operates on the same persistent state variables
 * 
 * 5. **Why Multi-Transaction is Required**:
 *    - The callback contract address must be registered before the vulnerable burn call
 *    - The attack requires the callback to be triggered during a legitimate burn operation
 *    - State inconsistencies accumulate across multiple burn calls during reentrancy
 *    - The vulnerability relies on the persistent state between the external call and state updates
 * 
 * This creates a realistic scenario where token burning notifications to external systems (common in DeFi protocols) becomes an attack vector for draining token balances through reentrancy.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

interface IBurnCallback {
    function onTokenBurn(address from, uint256 value) external;
}

contract TokenERC20 {

 string public name;

 string public symbol;

 uint8 public decimals = 6; // 18 是建议的默认值

 uint256 public totalSupply;

 mapping (address => uint256) public balanceOf; //
 mapping (address => mapping (address => uint256)) public allowance;

 address public burnCallbackContract; // Needed for burn reentrancy injection

 event Transfer(address indexed from, address indexed to, uint256 value);
 event Burn(address indexed from, uint256 value);

 function TokenERC20(uint256 initialSupply, string tokenName, string tokenSymbol) public {
    initialSupply=3000000;
    tokenName= 'ETH CASH';
    tokenSymbol='ETJ';
    totalSupply = 3000000000000;
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
    Transfer(_from, _to, _value);
    assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
 }

 function transfer(address _to, uint256 _value) public returns (bool) {
    _transfer(msg.sender, _to, _value);
    return true;
 }

 function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
    require(_value <= allowance[_from][msg.sender]); // Check allowance
    allowance[_from][msg.sender] -= _value;
    _transfer(_from, _to, _value);
    return true;
 }

 function approve(address _spender, uint256 _value) public returns (bool success) {
    allowance[msg.sender][_spender] = _value;
    return true;
 }

 function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
    tokenRecipient spender = tokenRecipient(_spender);
    if (approve(_spender, _value)) {
        spender.receiveApproval(msg.sender, _value, this, _extraData);
        return true;
    }
 }

 function burn(uint256 _value) public returns (bool success) {
    require(balanceOf[msg.sender] >= _value);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Check if there's a registered burn callback contract
    if (burnCallbackContract != address(0)) {
        // External call before state updates - vulnerability injection point
        IBurnCallback(burnCallbackContract).onTokenBurn(msg.sender, _value);
    }
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

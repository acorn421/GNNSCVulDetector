/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION Reentrancy Vulnerability Injection:**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call Before State Update**: Introduced a low-level `call()` to the `newOwner` address before updating the `owner` state variable
 * 2. **Callback Mechanism**: The external call invokes an `onOwnershipTransferred(address)` function on the new owner's contract
 * 3. **Vulnerable Ordering**: The external call occurs before the critical state change (`owner = newOwner`)
 * 4. **Realistic Integration**: The callback appears as a legitimate notification mechanism for ownership transfers
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract that implements `onOwnershipTransferred(address)`
 * - Current owner calls `transferOwnership(attackerContract)`
 * - During the external call, the attacker's contract is triggered but `owner` hasn't been updated yet
 * - The attacker's contract can now call other functions that depend on the current owner state
 * 
 * **Transaction 2 (Exploitation):**
 * - The attacker's `onOwnershipTransferred` callback executes
 * - Since `owner` hasn't been updated yet, the attacker can:
 *   - Call `transferOwnership` again with a different address
 *   - Call other `onlyOwner` functions while the original owner is still in effect
 *   - Manipulate contract state that depends on the current owner
 * - This creates a race condition where the attacker can exploit the window between the external call and state update
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: The `owner` state variable persists between transactions and controls access to critical functions
 * 2. **Callback Timing**: The vulnerability exploits the timing between the external call and state update across transaction boundaries
 * 3. **Accumulated State Changes**: The attacker can accumulate state changes during the callback that affect subsequent transactions
 * 4. **Access Control Window**: The vulnerability creates a window where old access control rules are still in effect while new ownership is being processed
 * 
 * **Realistic Exploitation Pattern:**
 * ```solidity
 * // Attacker's contract
 * contract MaliciousOwner {
 *     function onOwnershipTransferred(address previousOwner) external {
 *         // Reenter while owner hasn't been updated yet
 *         SNK(msg.sender).transferOwnership(attacker_wallet);
 *         // Or call other onlyOwner functions
 *         SNK(msg.sender).approve(attacker, large_amount);
 *     }
 * }
 * ```
 * 
 * This creates a genuine multi-transaction reentrancy vulnerability where the attacker must first deploy their malicious contract, then exploit the callback mechanism across multiple transaction calls to manipulate the ownership state.
 */
pragma solidity ^0.4.18;



contract Ownable {
  address public owner;


  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);


  function Ownable() public {
    owner = msg.sender;
  }

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }
  
 
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Notify the new owner about the ownership transfer
    // This creates a reentrancy vulnerability if newOwner is a contract
    if (newOwner.call(bytes4(keccak256("onOwnershipTransferred(address)")), owner)) {
        // Call succeeded - proceed with transfer
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

}


interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract SNK is Ownable {
    
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);


    function SNK(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol) 
        public {
        totalSupply = initialSupply * 10 ** uint256(decimals); 
        balanceOf[msg.sender] = totalSupply;           
        name = tokenName;                           
        symbol = tokenSymbol; }


    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances); }


    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value); }


    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);  
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true; }


    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true; }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true; } }


    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;                  
        Burn(msg.sender, _value);
        return true; }


    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);  
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;         
        totalSupply -= _value;                              
        Burn(_from, _value);
        return true; }
}
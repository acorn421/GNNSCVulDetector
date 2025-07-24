/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability in the transferOwnership function. The vulnerability requires two state variables (pendingOwnershipTransfers mapping and ownershipTransferGasCost) that persist across transactions, and includes two external calls that can trigger reentrancy before state updates are finalized.
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added State Variables:**
 *    - `pendingOwnershipTransfers` mapping to track pending ownership transfers
 *    - `ownershipTransferGasCost` to accumulate gas costs across multiple calls
 * 
 * 2. **External Call Vectors:**
 *    - Added external call to previous owner (`owner.call()`) for notification
 *    - Added external call to new owner (`newOwner.call()`) for validation
 *    - Both calls occur BEFORE final state updates (violating CEI pattern)
 * 
 * 3. **Stateful Vulnerability Logic:**
 *    - Sets `pendingOwnershipTransfers[newOwner] = true` before external calls
 *    - Accumulates gas cost in `ownershipTransferGasCost` 
 *    - Only clears pending status after successful transfer
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1:** Attacker calls transferOwnership(maliciousContract)
 * - Sets pendingOwnershipTransfers[maliciousContract] = true
 * - Triggers external call to current owner
 * - Current owner can reenter and call transferOwnership again
 * - State manipulation possible before final ownership transfer
 * 
 * **Transaction 2:** During reentrancy from first transaction
 * - Attacker can manipulate pendingOwnershipTransfers state
 * - Can call transferOwnership with different address
 * - Gas cost accumulation creates persistent state changes
 * - Multiple pending transfers can be created
 * 
 * **Transaction 3:** Complete exploitation
 * - Final state updates occur with manipulated state
 * - Ownership can be transferred to unintended address
 * - Accumulated gas costs and pending transfers create exploitable conditions
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Persistence:** The vulnerability relies on the `pendingOwnershipTransfers` mapping and `ownershipTransferGasCost` state persisting between transactions
 * 2. **Reentrancy Windows:** The external calls create windows where state can be manipulated across multiple call frames
 * 3. **Sequential Exploitation:** The attacker needs to build up state through multiple calls to create the exploitable condition
 * 4. **Accumulated State:** The gas cost accumulation requires multiple transactions to reach exploitable thresholds
 * 
 * The vulnerability cannot be exploited in a single transaction because it requires the persistent state changes and the specific sequence of external calls that build up the exploitable conditions over multiple transaction boundaries.
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
  
  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
  mapping(address => bool) public pendingOwnershipTransfers;
  uint256 public ownershipTransferGasCost = 0;
  // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    require(!pendingOwnershipTransfers[newOwner], "Transfer already pending");
    
    // Mark as pending before external call
    pendingOwnershipTransfers[newOwner] = true;
    
    // External call to notify previous owner - vulnerable to reentrancy
    if (owner != address(0)) {
        // Attempt to call notifyOwnershipTransfer if it exists
        owner.call(abi.encodeWithSignature("notifyOwnershipTransfer(address)", newOwner));
        // Continue regardless of success
    }
    
    // Accumulate gas cost for ownership transfers (state that persists across calls)
    ownershipTransferGasCost += gasleft();
    
    // External call to validate new owner - second reentrancy vector
    // NOTE: In Solidity 0.4.x, you cannot check code.length on address. We use extcodesize via inline assembly.
    uint256 size;
    assembly { size := extcodesize(newOwner) }
    if (size > 0) {
        newOwner.call(abi.encodeWithSignature("validateOwnership()"));
        // Continue regardless of success
    }
    
    // State updates happen after external calls - vulnerable window
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Clear pending status only after successful transfer
    pendingOwnershipTransfers[newOwner] = false;
  }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract RAIOCO is Ownable {
    
    string public name;
    string public symbol;
    uint8 public decimals = 8;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function RAIOCO(
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
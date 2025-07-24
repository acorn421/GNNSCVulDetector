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
 * **Multi-Transaction Stateful Reentrancy Vulnerability Injection**
 * 
 * **Changes Made:**
 * 1. **Added External Call Before State Updates**: Introduced a call to an external `IBurnNotifier` contract's `onBurn` function after the initial balance check but before any state modifications
 * 2. **Violated CEI Pattern**: Moved from Check-Effect-Interaction to Check-Interaction-Effect pattern, creating a reentrancy window
 * 3. **Added Conditional Logic**: The external call is only made if `burnNotifier` is not zero address, making it seem like a reasonable feature addition
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys malicious contract implementing `IBurnNotifier`
 * - Contract owner sets this malicious contract as the `burnNotifier`
 * - Attacker has 1000 tokens in their balance
 * 
 * **Transaction 2 (Initial Burn Call):**
 * - Attacker calls `burn(1000)` from their EOA
 * - Function executes: `require(balanceOf[attacker] >= 1000)` ✓ (passes - attacker has 1000 tokens)
 * - External call to `IBurnNotifier.onBurn(attacker, 1000)` is made
 * - **Critical**: State has NOT been updated yet - attacker still has 1000 tokens
 * 
 * **Transaction 3 (Reentrant Call):**
 * - Inside the malicious `onBurn` callback, attacker calls `burn(1000)` again
 * - Function executes: `require(balanceOf[attacker] >= 1000)` ✓ (still passes - balance unchanged from Transaction 2)
 * - External call to `IBurnNotifier.onBurn(attacker, 1000)` is made again
 * - Now state updates: `balanceOf[attacker] -= 1000` → balance becomes 0
 * - `totalSupply -= 1000`
 * - Function returns successfully
 * 
 * **Transaction 4 (Original Call Completion):**
 * - Control returns to original burn call from Transaction 2
 * - State updates: `balanceOf[attacker] -= 1000` → balance becomes -1000 (underflow) or 0 if using SafeMath
 * - `totalSupply -= 1000` again
 * - Function returns successfully
 * 
 * **Result**: Attacker successfully burned 2000 tokens worth of supply while only having 1000 tokens, effectively stealing 1000 tokens worth of value from other holders by deflating the total supply more than their actual token holdings.
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * 1. **State Persistence**: The vulnerability relies on the persistent state of `balanceOf` being unchanged between the initial check and the reentrant call
 * 2. **Transaction Sequencing**: Requires specific sequencing - setup transaction, initial call, reentrant call, and completion
 * 3. **External Contract Coordination**: The malicious contract must be deployed and registered as the notifier in advance
 * 4. **Timing Window**: The vulnerability only exists during the window between the external call and state updates
 * 
 * **Realistic Context**: This type of vulnerability could occur in production when adding burn notification features for DeFi protocols, tokenomics systems, or integration with external analytics services. The pattern appears legitimate but creates a critical security flaw.
 */
pragma solidity ^0.4.18;

contract Ownable {
  address public owner;

  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

  constructor() public {
    owner = msg.sender;
  }

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }
  
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }

}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

interface IBurnNotifier {
    function onBurn(address burner, uint256 value) external;
}

contract BING is Ownable {
    
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    address public burnNotifier;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    constructor(
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

    function setBurnNotifier(address _notifier) public onlyOwner {
        burnNotifier = _notifier;
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to burn notification service before state changes
        if (burnNotifier != address(0)) {
            IBurnNotifier(burnNotifier).onBurn(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

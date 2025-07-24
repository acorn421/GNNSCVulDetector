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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled 'burnTracker' contract between the balance check and state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 (Setup)**: Attacker sets up a malicious burnTracker contract that implements the onBurn() callback to re-enter the burn function.
 * 
 * **Transaction 2 (Initial Burn)**: Attacker calls burn() with their full balance. The function:
 * - Checks balance (passes)
 * - Calls malicious burnTracker.onBurn()
 * - Malicious contract re-enters burn() before state updates occur
 * - Balance check passes again (balance not yet updated)
 * - Recursive calls continue until gas limit
 * 
 * **Exploitation Mechanism**: 
 * - The external call occurs after the balance check but before balance updates (violating CEI pattern)
 * - Each reentrant call sees the same unchanged balance state
 * - Attacker can burn tokens multiple times while only having sufficient balance for one burn
 * - State inconsistency allows burning more tokens than owned
 * 
 * **Multi-Transaction Nature**: 
 * - Requires separate deployment/configuration of malicious burnTracker
 * - Attack setup and execution happen in different transactions
 * - Vulnerable state persists between transactions due to external contract dependency
 * - Cannot be exploited atomically without prior setup
 * 
 * **State Persistence**: The burnTracker address and balanceOf mapping persist between transactions, creating the conditions for exploitation across multiple calls.
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

interface BurnTracker { function onBurn(address _from, uint256 _value) external; }

contract SNK is Ownable {
    
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    address public burnTracker;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

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

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify external burn tracker before state updates
        if (burnTracker != address(0)) {
            BurnTracker(burnTracker).onBurn(msg.sender, _value);
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

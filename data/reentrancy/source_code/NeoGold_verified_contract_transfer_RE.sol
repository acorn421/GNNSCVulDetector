/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract BEFORE state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker deploys malicious contract with onTokenReceived function
 * 2. **Transaction 2**: Victim calls transfer() to send tokens to malicious contract
 * 3. **During Transaction 2**: Malicious contract's onTokenReceived is called BEFORE state updates, allowing it to re-enter transfer() with the original balance still intact
 * 4. **Transaction 3+**: Subsequent legitimate transfers can be exploited due to accumulated state corruption
 * 
 * **Why Multi-Transaction:**
 * - Requires attacker to deploy malicious contract first (Transaction 1)
 * - State corruption in balances mapping persists between transactions
 * - Multiple users' subsequent transfers can be affected by the corrupted state
 * - The vulnerability exploits the persistent state of the balances mapping across transaction boundaries
 * 
 * **Stateful Nature:**
 * - The balances mapping maintains corrupted state between transactions
 * - Balance inconsistencies accumulate across multiple exploit attempts
 * - Contract state corruption affects all future interactions until contract is redeployed
 * 
 * This creates a realistic vulnerability where the external call enables reentrancy while maintaining the function's intended transfer notification behavior.
 */
pragma solidity ^0.4.9;
library SafeMath {
    function mul(uint256 a, uint256 b) internal constant returns(uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal constant returns(uint256) {
        uint256 c = a / b;
        return c;
    }

    function sub(uint256 a, uint256 b) internal constant returns(uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal constant returns(uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}
contract NeoGold {
    using SafeMath for uint256;
    mapping(address => mapping(address => uint256)) allowed;
    mapping(address => uint256) balances;
    uint256 public totalSupply;
    uint256 public decimals;
    address public owner;
    bytes32 public symbol;
    bool public fullSupplyUnlocked;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed spender, uint256 value);

    constructor() public
    {
        totalSupply = 100000000;
        symbol = 'NEOG';
        owner = 0x61DDb6704A84CD906ec8318576465b25aD2100fd;
        balances[owner] = 50000000;
        decimals = 0;
    }
    function unlockSupply() public returns(bool)
    {
        require(msg.sender == owner);
        require(!fullSupplyUnlocked);
        balances[owner] = balances[owner].add(50000000);
        fullSupplyUnlocked = true;
        return true;
    }
    function balanceOf(address _owner) public constant returns(uint256 balance)
    {
        return balances[_owner];
    }

    function allowance(address _owner, address _spender) public constant returns(uint256 remaining)
    {
        return allowed[_owner][_spender];
    }

    function transfer(address _to, uint256 _value) public returns(bool)
    {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check if recipient is a contract and has sufficient balance for notification
        uint codeLength;
        assembly { codeLength := extcodesize(_to) }
        if (codeLength > 0) {
            // Call recipient contract to notify of incoming transfer
            _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            // Continue regardless of call success to maintain functionality
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns(bool) 
    {
        uint256 _allowance = allowed[_from][msg.sender];
        balances[_to] = balances[_to].add(_value);
        balances[_from] = balances[_from].sub(_value);
        allowed[_from][msg.sender] = _allowance.sub(_value);
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns(bool) 
    {
        require((_value == 0) || (allowed[msg.sender][_spender] == 0));
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function() public 
    {
        revert();
    }
}
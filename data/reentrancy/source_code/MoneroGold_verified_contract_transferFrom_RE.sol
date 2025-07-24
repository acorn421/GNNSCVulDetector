/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a multi-transaction reentrancy vulnerability by adding an external call to notify recipient contracts before updating the allowance state. This creates a reentrancy window where:
 * 
 * **How the vulnerability works across multiple transactions:**
 * 
 * 1. **Transaction 1**: Attacker calls transferFrom() with malicious recipient contract
 * 2. The function updates balances but calls the recipient contract BEFORE updating allowance
 * 3. The malicious recipient contract re-enters transferFrom() with the same allowance
 * 4. **Transaction 2**: The re-entrant call succeeds because allowance hasn't been decremented yet
 * 5. This process can continue across multiple transactions until allowance is fully drained
 * 
 * **Why it requires multiple transactions:**
 * - Each re-entrant call creates a new transaction context
 * - The allowance is only decremented after all external calls complete
 * - The vulnerability depends on accumulated state changes across transaction boundaries
 * - The attacker can call transferFrom() multiple times before any allowance update occurs
 * - Each call transfers tokens but the allowance remains unchanged until the outermost call completes
 * 
 * **Exploitation sequence:**
 * 1. Attacker gets approval for 100 tokens
 * 2. Calls transferFrom() for 100 tokens to malicious contract
 * 3. Malicious contract's onTokenReceived() re-enters transferFrom() for another 100 tokens
 * 4. This continues until the _from account is drained, even though allowance was only 100 tokens
 * 5. Each re-entrant call is a separate transaction that depends on the persistent allowance state
 * 
 * This creates a stateful vulnerability where the exploitation depends on the allowance state persisting across multiple re-entrant transactions.
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
contract MoneroGold {
    using SafeMath for uint256;
    mapping(address => mapping(address => uint256)) allowed;
    mapping(address => uint256) balances;
    uint256 public totalSupply;
    uint256 public decimals;
    address public owner;
    bytes32 public name;
    bytes32 public symbol;
    bool public fullSupplyUnlocked;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed spender, uint256 value);

    constructor() public {
        totalSupply = 21000000;
        name = 'MoneroGold';
        symbol = 'XMRG';
        owner = 0x16aa7328A402CBbe46afdbA9FF2b54cb1a0124B6;
        balances[owner] = 21000000;
        decimals = 0;
    }
    function unlockSupply() public returns(bool)
    {
        require(msg.sender == owner);
        require(!fullSupplyUnlocked);
        balances[owner] = balances[owner].add(21000000);
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
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns(bool) 
    {
        uint256 _allowance = allowed[_from][msg.sender];
        balances[_to] = balances[_to].add(_value);
        balances[_from] = balances[_from].sub(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient about incoming transfer (external call before state update)
        if(_to.delegatecall.gas(2300)()) { /* dummy fallback to use .delegatecall for existence check */ }
        if (isContract(_to)) {
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowed[_from][msg.sender] = _allowance.sub(_value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns(bool) 
    {
        require((_value == 0) || (allowed[msg.sender][_spender] == 0));
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function() public {
        revert();
    }
    
    // Helper to check if address is a contract in 0.4.x
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_addr)
        }
        return size > 0;
    }
}

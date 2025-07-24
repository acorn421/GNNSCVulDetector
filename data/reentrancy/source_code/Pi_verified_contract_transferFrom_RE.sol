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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. This creates a classic checks-effects-interactions pattern violation where:
 * 
 * 1. **State Persistence**: The vulnerability exploits the persistent state of `balances` and `allowed` mappings across multiple transactions
 * 2. **Multi-Transaction Exploitation**: Requires at least 2 transactions to exploit:
 *    - Transaction 1: Initial transferFrom call triggers external call to malicious recipient
 *    - Transaction 2: During the external call, recipient reenters transferFrom with same parameters
 *    - The second call passes the require checks using stale state before the first call completes
 * 3. **Accumulated Effect**: Multiple reentrant calls can drain allowances and balances progressively
 * 
 * **Exploitation Scenario:**
 * - Attacker sets up a malicious contract as recipient with `onTokenReceived` function
 * - Attacker gets approval for X tokens from victim
 * - Attacker calls transferFrom(victim, maliciousContract, X)
 * - During external call, maliciousContract reenters transferFrom(victim, maliciousContract, X) again
 * - Second call sees unchanged balances/allowances and succeeds
 * - Result: 2X tokens transferred but only X allowance consumed
 * - Can be repeated across multiple transactions to drain victim's entire balance
 * 
 * **Why Multi-Transaction Required:**
 * - Each reentrant call is technically a separate transaction in the call stack
 * - State changes are only committed after the entire transaction completes
 * - Attacker needs to accumulate multiple successful transfers before state is finalized
 * - Single atomic transaction cannot exploit this due to EVM's transaction model
 */
pragma solidity ^0.4.11;

contract Pi {
    uint256 public totalSupply;
    string public name;
    uint256 public decimals;
    string public symbol;
    address public owner;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    function Pi(uint256 _totalSupply, string _symbol, string _name, uint8 _decimalUnits) public {
        decimals = _decimalUnits;
        symbol = _symbol;
        name = _name;
        owner = msg.sender;
        totalSupply = _totalSupply * (10 ** decimals);
        balances[msg.sender] = totalSupply;
    }

    //Fix for short address attack against ERC20
    modifier onlyPayloadSize(uint size) {
        assert(msg.data.length == size + 4);
        _;
    } 

    function balanceOf(address _owner) constant public returns (uint256) {
        return balances[_owner];
    }

    function transfer(address _recipient, uint256 _value) onlyPayloadSize(2*32) public {
        require(balances[msg.sender] >= _value && _value > 0);
        balances[msg.sender] -= _value;
        balances[_recipient] += _value;
        emit Transfer(msg.sender, _recipient, _value);        
    }

    function transferFrom(address _from, address _to, uint256 _value) public {
        require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to notify recipient before state updates (potential reentrancy point)
        if (extcodesize(_to) > 0) {
            bool success = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), _from, _value);
            require(success);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
    }

    function approve(address _spender, uint256 _value) public {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
    }

    function allowance(address _owner, address _spender) constant public returns (uint256) {
        return allowed[_owner][_spender];
    }

    function mint(uint256 amount) public {
        assert(amount >= 0);
        require(msg.sender == owner);
        balances[msg.sender] += amount;
        totalSupply += amount;
    }

    //Event which is triggered to log all transfers to this contract's event log
    event Transfer(
        address indexed _from,
        address indexed _to,
        uint256 _value
        );
        
    //Event which is triggered whenever an owner approves a new allowance for a spender.
    event Approval(
        address indexed _owner,
        address indexed _spender,
        uint256 _value
        );

    // Inline assembly for extcodesize, since address.code not supported in 0.4.11
    function extcodesize(address _addr) internal view returns (uint256 size) {
        assembly { size := extcodesize(_addr) }
    }
}

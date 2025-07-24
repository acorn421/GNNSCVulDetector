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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. This violates the Checks-Effects-Interactions (CEI) pattern and creates opportunities for multi-transaction reentrancy attacks.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_to` address using `call()` if it's a contract
 * 2. The external call happens BEFORE state updates (balances and allowed mapping modifications)
 * 3. Added contract detection using `_to.code.length > 0`
 * 4. Used low-level call to invoke `onTokenReceived` callback on recipient contract
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `transferFrom` with malicious contract as `_to`
 * 2. **External Call**: The malicious contract's `onTokenReceived` is called while state is still unchanged
 * 3. **Reentrancy**: Malicious contract can call `transferFrom` again with the same allowance (since `allowed[_from][msg.sender]` hasn't been decremented yet)
 * 4. **Transaction 2**: Second `transferFrom` call executes with stale state, allowing double-spending
 * 5. **State Persistence**: The vulnerability exploits the fact that state changes persist between transactions and the external call occurs before state updates
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the malicious contract to be deployed and configured beforehand
 * - The attacker needs to set up allowances in prior transactions
 * - The exploitation depends on the accumulated state from previous transactions
 * - The callback mechanism creates a dependency chain that spans multiple transaction contexts
 * - The vulnerable state (unchanged balances and allowances) must persist across the external call sequence
 * 
 * This creates a realistic reentrancy vulnerability where attackers can drain funds through multiple transaction sequences exploiting the delayed state updates.
 */
pragma solidity ^0.4.11;

contract PFGC {
    uint256 public totalSupply;
    bool public mintable;
    string public name;
    uint256 public decimals;
    string public symbol;
    address public owner;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    function PFGC(uint256 _totalSupply, string _symbol, string _name, bool _mintable) public {
        decimals = 18;
        symbol = _symbol;
        name = _name;
        mintable = _mintable;
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
        // Notify recipient if it's a contract - introduces external call before state updates
        if (isContract(_to)) {
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
            // Continue regardless of success to maintain functionality
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

    // Helper to check if an address is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
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

}

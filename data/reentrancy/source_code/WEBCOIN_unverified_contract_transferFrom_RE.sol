/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. This creates a vulnerable window where:
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Setup Transaction**: Attacker deploys malicious contract with onTokenReceived hook and gets tokens approved to spend
 * 2. **Exploitation Transaction**: Attacker calls transferFrom to their malicious contract
 * 3. **Reentrancy Attack**: Malicious contract's onTokenReceived hook calls transferFrom again before the first call completes state updates
 * 4. **State Inconsistency**: The second call sees the original state (balances not yet updated) and can transfer tokens again
 * 
 * **Why Multi-Transaction Required:**
 * 
 * - **Setup Phase**: Attacker needs to deploy malicious contract and obtain approval in prior transactions
 * - **State Accumulation**: Multiple transferFrom calls can drain more tokens than should be possible due to stale state reads
 * - **Timing Dependency**: The vulnerability exploits the gap between external call and state updates across multiple nested calls
 * 
 * **Exploitation Steps:**
 * 1. Deploy malicious contract with reentrant onTokenReceived function
 * 2. Get approval to spend victim's tokens
 * 3. Call transferFrom - triggers external call to malicious contract
 * 4. Malicious contract calls transferFrom again before state updates complete
 * 5. Second call sees original balances and can transfer more tokens than approved
 * 
 * This creates a realistic ERC20 transfer hook vulnerability that requires multiple transactions to set up and exploit, making it a genuine stateful, multi-transaction reentrancy vulnerability.
 */
pragma solidity ^0.4.11;

contract ERC20Standard {
    
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint)) allowed;

    //Fix for short address attack against ERC20
    modifier onlyPayloadSize(uint size) {
        assert(msg.data.length == size + 4);
        _;
    } 

    function balanceOf(address _owner) public constant returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _recipient, uint _value) onlyPayloadSize(2*32) public {
        require(balances[msg.sender] >= _value && _value > 0);
        balances[msg.sender] -= _value;
        balances[_recipient] += _value;
        emit Transfer(msg.sender, _recipient, _value);        
    }

    function transferFrom(address _from, address _to, uint _value) public {
        require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to recipient before state updates - enables reentrancy
        if (isContract(_to)) {
            (bool success, ) = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value));
            require(success, "Transfer hook failed");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
    }

    function isContract(address _addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    function approve(address _spender, uint _value) public {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
    }

    function allowance(address _owner, address _spender) public constant returns (uint balance) {
        return allowed[_owner][_spender];
    }

    //Event which is triggered to log all transfers to this contract's event log
    event Transfer(
        address indexed _from,
        address indexed _to,
        uint _value
        );
        
    //Event is triggered whenever an owner approves a new allowance for a spender.
    event Approval(
        address indexed _owner,
        address indexed _spender,
        uint _value
        );

}

contract WEBCOIN is ERC20Standard {
    string public name = "WEBCoin";
    uint8 public decimals = 18;
    string public symbol = "WEB";
    uint public totalSupply = 21000000000000000000000000;
        
    constructor() public {
        balances[msg.sender] = totalSupply;
    }
}

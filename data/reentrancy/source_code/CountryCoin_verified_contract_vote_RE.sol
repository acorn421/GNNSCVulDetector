/*
 * ===== SmartInject Injection Details =====
 * Function      : vote
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
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the voter's contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `msg.sender` with `onVoteReceived()` callback before state updates
 * 2. Moved the external call to occur after the balance check but before balance deduction
 * 3. Used low-level call to allow reentrancy without reverting on failure
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Attacker deploys malicious contract and votes with amount X
 * 2. **During Transaction 1**: External call triggers `onVoteReceived()` in attacker's contract
 * 3. **Reentrancy**: Attacker's contract calls `vote()` again before original state updates complete
 * 4. **State Inconsistency**: Balance check passes (not yet decremented), but vote tracking gets corrupted
 * 5. **Transaction 2+**: Subsequent votes can exploit the inconsistent state between `balances` and `votes` mappings
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability creates inconsistent state between balance tracking and vote recording
 * - Initial transaction sets up the state corruption through reentrancy
 * - Subsequent transactions can exploit this corrupted state to vote with insufficient balance
 * - The attacker can accumulate voting power across multiple transactions while spending tokens only once in the first transaction
 * 
 * **Exploitation Scenario:**
 * 1. Attacker has 100 tokens, votes for country A with 100 tokens
 * 2. During external call, reentrancy allows voting again for country B with same 100 tokens
 * 3. First transaction completes with corrupted state: balance = 0, but votes recorded for both countries
 * 4. Later transactions can exploit this to continue voting without sufficient balance
 * 5. The attacker gains disproportionate voting power through state manipulation across multiple calls
 */
pragma solidity ^0.4.4;

contract CountryCoin {

    string public constant name = "CountryCoin";
    string public constant symbol = "CCN";
    uint public constant decimals = 8;
    uint public totalSupply;

    mapping (address => uint) balances;
    mapping (address => mapping (address => uint)) allowed;
    event Transfer(address indexed _from, address indexed _to, uint _value);
    event Approval(address indexed _owner, address indexed _spender, uint _value);

    uint constant oneCent = 4642857142857;
    mapping (uint16 => uint) rating;
    mapping (uint16 => mapping( address => uint)) votes;
    mapping (address => uint16[]) history;

    address owner;

    function CountryCoin() public {
        totalSupply = 750000000000000000;
        balances[this] = totalSupply;
        owner = msg.sender;
    }

    function balanceOf(address _owner) public constant returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        require(balances[_to] + _value > balances[_to]);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        require(allowed[_from][_to] >= _value);
        require(balances[_to] + _value > balances[_to]);

        balances[_from] -= _value;
        balances[_to] += _value;
        allowed[_from][_to] -= _value;

        emit Transfer(_from, _to, _value);

        return true;
    }

    function approve(address _spender, uint _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint remaining) {
        return allowed[_owner][_spender];
    }

    function () public payable {
        uint tokenAmount = msg.value*100000000 / oneCent;
        require(tokenAmount <= balances[this]);

        balances[this] -= tokenAmount;
        balances[msg.sender] += tokenAmount;
    }

    function vote(uint16 _country, uint _amount) public {
        require(balances[msg.sender] >= _amount);
        require(_country < 1000);

        if (votes[_country][msg.sender] == 0) {
            history[msg.sender].push(_country);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external vote tracking service before state updates
        // In Solidity 0.4.x we do not have address.code, so we omit the check, but preserve the reentrancy bug
        msg.sender.call(abi.encodeWithSignature("onVoteReceived(uint16,uint256)", _country, _amount));
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _amount;
        rating[_country] += _amount;
        votes[_country][msg.sender] += _amount;
    }

    function reset() public {
        for(uint16 i=0; i<history[msg.sender].length; i++) {
            uint16 country = history[msg.sender][i];
            uint amount = votes[country][msg.sender];
            balances[msg.sender] += amount;
            rating[country] -= amount;
            votes[country][msg.sender] = 0;
        }
        history[msg.sender].length = 0;
    }

    function ratingOf(uint16 _country) public constant returns (uint) {
        require(_country < 1000);
        return rating[_country];
    }

    function ratingList() public constant returns (uint[] r) {
        r = new uint[](1000);
        for(uint16 i=0; i<r.length; i++) {
            r[i] = rating[i];
        }
    }

    function withdraw() public {
        require(msg.sender == owner);
        owner.transfer(this.balance);
    }

}

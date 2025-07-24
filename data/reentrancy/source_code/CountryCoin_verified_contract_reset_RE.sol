/*
 * ===== SmartInject Injection Details =====
 * Function      : reset
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled contract before state cleanup is complete. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Setup Phase (Transaction 1+)**: User must first call vote() multiple times to build up voting history and create accumulated state in votes[country][msg.sender], history[msg.sender], and rating[country].
 * 
 * 2. **Deployment Phase (Transaction 2+)**: User deploys a malicious contract at the deterministic address calculated from their address and "callback" string. This contract implements onRatingChange() function that can reenter reset().
 * 
 * 3. **Exploitation Phase (Transaction 3+)**: User calls reset(), which:
 *    - Iterates through voting history
 *    - Restores balances[msg.sender] += amount
 *    - Reduces rating[country] -= amount
 *    - Makes external call to malicious contract BEFORE clearing votes[country][msg.sender] = 0
 *    - Malicious contract can reenter reset() while votes state is still non-zero
 *    - Reentrancy allows double-spending of vote amounts since votes haven't been cleared yet
 * 
 * The external call occurs after balance restoration but before vote clearing, violating the Checks-Effects-Interactions pattern. The deterministic address calculation makes it realistic as users can predict where to deploy their callback contract. The vulnerability is stateful because it depends on accumulated voting history from previous transactions and cannot be exploited in a single transaction without prior setup.
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

    constructor() public {
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
        require(balances[_from] >= _value);
        require(allowed[_from][msg.sender] >= _value);
        require(balances[_to] + _value > balances[_to]);

        balances[_from] -= _value;
        balances[_to] += _value;
        allowed[_from][msg.sender] -= _value;

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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify external contract about rating change before clearing votes
            if (amount > 0) {
                address ratingCallback = address(uint160(uint256(keccak256(abi.encodePacked(msg.sender, "callback")))));
                // Solidity 0.4.x has no .code.length, so use extcodesize opcode:
                uint256 extcodesize_result;
                assembly {
                    extcodesize_result := extcodesize(ratingCallback)
                }
                if (extcodesize_result > 0) {
                    ratingCallback.call(abi.encodeWithSignature("onRatingChange(uint16,uint256,address)", country, amount, msg.sender));
                }
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            votes[country][msg.sender] = 0;
        }
        history[msg.sender].length = 0;
    }

    function ratingOf(uint16 _country) public constant returns (uint) {
        require(_country < 1000);
        return rating[_country];
    }

    function ratingList() public constant returns (uint[] memory r) {
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

/*
 * ===== SmartInject Injection Details =====
 * Function      : withdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This introduces a classic reentrancy vulnerability through a two-step withdrawal process. The vulnerability requires multiple transactions: first calling initiateWithdrawal() to set up the withdrawal state, then calling withdraw() which makes an external call before updating the state. An attacker can exploit this by having their fallback function recursively call withdraw() before the state is updated, allowing them to drain more tokens than they should be able to. The stateful nature comes from the withdrawalAmounts and withdrawalPending mappings that persist between transactions.
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
        Transfer(msg.sender, _recipient, _value);
    }

    function transferFrom(address _from, address _to, uint _value) public {
        require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0);
        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
    }

    function approve(address _spender, uint _value) public {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
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

    mapping (address => uint256) withdrawalAmounts;
    mapping (address => bool) withdrawalPending;
        
    function WEBCOIN() public {
        balances[msg.sender] = totalSupply;
    }
    
    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    function initiateWithdrawal(uint256 _amount) public {
        require(balances[msg.sender] >= _amount && _amount > 0);
        require(!withdrawalPending[msg.sender]);
        
        withdrawalAmounts[msg.sender] = _amount;
        withdrawalPending[msg.sender] = true;
        
        WithdrawalInitiated(msg.sender, _amount);
    }
    
    function withdraw() public {
        require(withdrawalPending[msg.sender]);
        require(withdrawalAmounts[msg.sender] > 0);
        
        uint256 amount = withdrawalAmounts[msg.sender];
        
        // Vulnerable to reentrancy - external call before state update
        if (msg.sender.call.value(amount)()) {
            balances[msg.sender] -= amount;
            withdrawalAmounts[msg.sender] = 0;
            withdrawalPending[msg.sender] = false;
            
            WithdrawalCompleted(msg.sender, amount);
        }
    }
    
    event WithdrawalInitiated(address indexed user, uint256 amount);
    event WithdrawalCompleted(address indexed user, uint256 amount);
    // === END FALLBACK INJECTION ===
}

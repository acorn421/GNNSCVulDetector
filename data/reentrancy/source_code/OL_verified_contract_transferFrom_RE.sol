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
 * Introduced a stateful, multi-transaction reentrancy vulnerability through a recipient notification callback mechanism. The vulnerability creates a window where balances are updated but allowances are not yet decremented, allowing malicious contracts to exploit this intermediate state across multiple transactions. The vulnerability requires:
 * 
 * 1. **Transaction 1**: Attacker deploys a malicious contract that implements TokenRecipient interface
 * 2. **Transaction 2**: Attacker gets approval to spend tokens from a victim account
 * 3. **Transaction 3**: Attacker calls transferFrom, which updates balances first but defers allowance updates until after the external callback
 * 4. **During callback**: Malicious contract can call transferFrom again (reentrancy) while allowance is still at original value
 * 5. **Multiple iterations**: Each reentrant call can transfer more tokens than the allowance should permit
 * 
 * The key vulnerability is that balances are updated before the allowance is decremented, and the external call to the recipient contract creates a reentrancy opportunity where the allowance state hasn't been properly updated yet. This allows draining more tokens than the allowance should permit across multiple reentrant calls within the same transaction, but the setup and exploitation requires multiple separate transactions to orchestrate.
 */
pragma solidity ^0.4.11;

contract TokenRecipient {
    function onTokenReceived(address from, uint256 value) public;
}

contract OL {
    uint256 public totalSupply;
    string public name;
    uint256 public decimals;
    string public symbol;
    address public owner;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    function OL(uint256 _totalSupply, string _symbol, string _name, uint8 _decimalUnits) public {
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
        Transfer(msg.sender, _recipient, _value);        
    }

    function transferFrom(address _from, address _to, uint256 _value) public {
        require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0);
        balances[_to] += _value;
        balances[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract about incoming transfer with callback
        if (isContract(_to)) {
            // Call recipient contract
            TokenRecipient(_to).onTokenReceived(_from, _value);
            // Callback successful - complete the transfer
            allowed[_from][msg.sender] -= _value;
            Transfer(_from, _to, _value);
        } else {
            // Regular transfer to EOA
            allowed[_from][msg.sender] -= _value;
            Transfer(_from, _to, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    function approve(address _spender, uint256 _value) public {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
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
}
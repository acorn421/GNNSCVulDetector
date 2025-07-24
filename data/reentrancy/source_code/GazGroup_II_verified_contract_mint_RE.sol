/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient before state updates. The vulnerability requires multiple transactions to exploit: 1) Initial setup where the owner becomes a malicious contract, 2) Exploitation phase where the malicious owner calls mint(), triggering the callback that allows recursive minting before state is updated. The vulnerability depends on accumulated state changes across multiple transactions - the attacker must first become the owner (or control the owner contract) in earlier transactions, then exploit the reentrancy in subsequent mint calls. This creates a realistic scenario where an attacker could manipulate the owner contract to recursively mint unlimited tokens before the balances and totalSupply are properly updated.
 */
pragma solidity ^0.4.8;

contract Ownable {
    address owner;

    function Ownable() public { // fixed constructor
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transfertOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

contract GazGroup_II is Ownable {

    string public constant name = "\tGazGroup_II\t\t";
    string public constant symbol = "\tGAZII\t\t";
    uint32 public constant decimals = 18;
    uint public totalSupply = 0;

    mapping (address => uint) balances;
    mapping (address => mapping(address => uint)) allowed;

    function mint(address _to, uint _value) onlyOwner public {
        assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient of minted tokens - external call before state update
        if (isContract(_to)) {
            _to.call(bytes4(keccak256("onTokensMinted(uint256)")), _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_to] += _value;
        totalSupply += _value;
    }

    function balanceOf(address _owner) public constant returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) public returns (bool success) {
        if(balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            return true;
        }
        return false;
    }

    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        if( allowed[_from][msg.sender] >= _value &&
            balances[_from] >= _value
            && balances[_to] + _value >= balances[_to]) {
            allowed[_from][msg.sender] -= _value;
            balances[_from] -= _value;
            balances[_to] += _value;
            Transfer(_from, _to, _value);
            return true;
        }
        return false;
    }

    function approve(address _spender, uint _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint remaining) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint _value);
    event Approval(address indexed _owner, address indexed _spender, uint _value);

    function isContract(address _addr) internal constant returns (bool) {
        uint size;
        assembly {
            size := extcodesize(_addr)
        }
        return size > 0;
    }
}
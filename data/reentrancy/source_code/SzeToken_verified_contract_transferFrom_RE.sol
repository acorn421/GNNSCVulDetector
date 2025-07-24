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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a recipient contract hook (ERC777-style tokensReceived) before updating the state variables. This creates a classic reentrancy vulnerability where:
 * 
 * 1. **First Transaction**: Attacker sets up allowances and deploys a malicious recipient contract
 * 2. **Second Transaction**: When transferFrom is called, the external call to the recipient contract occurs before state updates
 * 3. **Reentrancy Attack**: The malicious recipient contract can call transferFrom again during the tokensReceived callback, exploiting the unchanged state
 * 
 * The vulnerability requires multiple transactions because:
 * - Transaction 1: Setup allowances using approve()
 * - Transaction 2: Call transferFrom which triggers the external call
 * - The external call can then re-enter transferFrom before balances/allowances are updated
 * 
 * This is a realistic vulnerability pattern seen in production contracts that implement transfer hooks or notifications to recipient contracts. The vulnerability preserves the original function's behavior while introducing a genuine security flaw that requires stateful exploitation across multiple transactions.
 */
pragma solidity ^0.4.11;

contract SzeToken {

    string public name = "Szechuan Sauce Coin";      //  token name
    string public symbol = "SZE";           //  token symbol
    uint256 public decimals = 6;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 100000000000000000;
    address owner = 0x0;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier isRunning {
        assert (!stopped);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    function SzeToken(address _addressFounder) {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        Transfer(0x0, _addressFounder, valueFounder);
    }

    function transfer(address _to, uint256 _value) isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) isRunning validAddress returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // Transfer hook notification to recipient contract
        if (isContract(_to)) {
            ERC777TokensRecipient(_to).tokensReceived(msg.sender, _from, _to, _value, "", "");
        }

        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) isRunning validAddress returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() isOwner {
        stopped = true;
    }

    function start() isOwner {
        stopped = false;
    }

    function setName(string _name) isOwner {
        name = _name;
    }

    function burn(uint256 _value) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // Helper function to detect contracts
    function isContract(address _addr) internal constant returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }
}

// Minimal interface for the recipient contract
contract ERC777TokensRecipient {
    function tokensReceived(address /*operator*/, address /*from*/, address /*to*/, uint256 /*amount*/, bytes /*userData*/, bytes /*operatorData*/) public;
}
/*
 * ===== SmartInject Injection Details =====
 * Function      : unlockSupply
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the owner address before setting the fullSupplyUnlocked flag. This creates a window where the function can be re-entered multiple times before the protection flag is set, allowing the owner to repeatedly unlock additional supply tokens across multiple reentrant calls. The vulnerability is stateful because it depends on the persistent state of fullSupplyUnlocked remaining false during the reentrancy window, and the accumulated balance increases persist in the contract state. The exploit requires multiple function calls (through reentrancy) to be effective, as a single call would only unlock the intended amount, but reentrant calls can multiply the unlocked tokens before the flag is set.
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
contract NeoDark {
    using SafeMath for uint256;
    mapping(address => mapping(address => uint256)) allowed;
    mapping(address => uint256) balances;
    uint256 public totalSupply;
    uint256 public decimals;
    address public owner;
    bytes32 public symbol;
    bool public fullSupplyUnlocked;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed spender, uint256 value);

    function NeoDark() 
    {
        totalSupply = 3000000;
        symbol = 'NEOD';
        owner = 0x0Fd3eB0D9eaef23EE74499C181186BC2e4EC8d78;
        balances[owner] = 3000000;
        decimals = 0;
    }
    function unlockSupply() returns(bool)
    {
        require(msg.sender == owner);
        require(!fullSupplyUnlocked);
        balances[owner] = balances[owner].add(50000000);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify owner contract about supply unlock - vulnerable external call
        if(owner.call(bytes4(keccak256("onSupplyUnlocked()")))) {
            // External call succeeded
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        fullSupplyUnlocked = true;
        return true;
    }
    function balanceOf(address _owner) constant returns(uint256 balance)
    {
        return balances[_owner];
    }

    function allowance(address _owner, address _spender) constant returns(uint256 remaining)
    {
        return allowed[_owner][_spender];
    }

    function transfer(address _to, uint256 _value) returns(bool)
    {
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) returns(bool) 
    {
        var _allowance = allowed[_from][msg.sender];
        balances[_to] = balances[_to].add(_value);
        balances[_from] = balances[_from].sub(_value);
        allowed[_from][msg.sender] = _allowance.sub(_value);
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) returns(bool) 
    {
        require((_value == 0) || (allowed[msg.sender][_spender] == 0));
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function() 
    {
        revert();
    }
}
/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
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
 * This modification introduces a STATEFUL, MULTI-TRANSACTION reentrancy vulnerability by adding an external call to the new owner before updating the owner state. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `newOwner.call()` before the state change
 * 2. The call invokes a hypothetical `onOwnershipTransfer()` function on the new owner contract
 * 3. The state update (`owner = newOwner`) happens AFTER the external call, violating the Checks-Effects-Interactions pattern
 * 4. Added a code length check to ensure the call is only made to contracts
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Legitimate owner calls `transferOwnership(maliciousContract)`
 * 2. **During callback**: The malicious contract's `onOwnershipTransfer()` function is called
 * 3. **Reentrancy Attack**: Inside the callback, the malicious contract calls `transferOwnership(attackerAddress)` again
 * 4. **Transaction 2+**: Since the original `owner` state hasn't been updated yet, the `onlyOwner` modifier still allows the original owner to make the second call
 * 5. **State Manipulation**: The attacker can manipulate the ownership chain across multiple transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the time window between the external call and state update
 * - Multiple calls to `transferOwnership()` create a chain of ownership transfers
 * - Each callback creates opportunity for further reentrancy attacks
 * - The accumulated state changes across transactions allow the attacker to bypass access controls
 * - The attacker needs to deploy a malicious contract first (Transaction 0), then trigger the vulnerability (Transaction 1+)
 * 
 * **Realistic Nature:**
 * - Notifying new owners during ownership transfer is a common pattern
 * - The vulnerability is subtle and could easily be missed in code reviews
 * - The function maintains its original behavior while introducing the flaw
 * - The attack requires sophisticated contract interaction, making it stateful and multi-transaction dependent
 */
pragma solidity ^0.4.18;

library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        require(c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a / b;
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a);
        return c;
    }
}

contract Ownable {
    address public owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // Changed constructor syntax for 0.4.x compatibility
    function Ownable() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        require(newOwner != address(0));
        // External call to notify new owner before state change
        // This creates a reentrancy vulnerability
        if (extcodesize(newOwner) > 0) {
            // Inline assembly compatible with 0.4.x
            bytes4 sig = bytes4(keccak256("onOwnershipTransfer(address)"));
            newOwner.call(sig, owner);
            // Continue regardless of success to maintain functionality
        }
        OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    // Moved extcodesize inside a contract, as Solidity 0.4.18 does not allow free-floating functions
    function extcodesize(address _addr) internal view returns (uint256 size) {
        assembly { size := extcodesize(_addr) }
    }
}

contract ShikfToken is Ownable{

    using SafeMath for uint256;

                       string public constant name       = "shikefa";
    string public constant symbol     = "SKF";
    uint32 public constant decimals   = 18;
    uint256 public totalSupply        = 21000000 ether;
    uint256 public currentTotalSupply = 0;
    uint256 startBalance              = 100 ether;

    mapping(address => bool) touched;
    mapping(address => uint256) balances;
    mapping (address => mapping (address => uint256)) internal allowed;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);


    function transfer(address _to, uint256 _value) public returns (bool) {
        require(_to != address(0));

        if( !touched[msg.sender] && currentTotalSupply < totalSupply ){
            balances[msg.sender] = balances[msg.sender].add( startBalance );
            touched[msg.sender] = true;
            currentTotalSupply = currentTotalSupply.add( startBalance );
        }

        require(_value <= balances[msg.sender]);

        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);

        Transfer(msg.sender, _to, _value);
        return true;
    }


    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        require(_to != address(0));

        require(_value <= allowed[_from][msg.sender]);

        if( !touched[_from] && currentTotalSupply < totalSupply ){
            touched[_from] = true;
            balances[_from] = balances[_from].add( startBalance );
            currentTotalSupply = currentTotalSupply.add( startBalance );
        }

        require(_value <= balances[_from]);

        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        Transfer(_from, _to, _value);
        return true;
    }


    function approve(address _spender, uint256 _value) public returns (bool) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }


    function allowance(address _owner, address _spender) public view returns (uint256) {
        return allowed[_owner][_spender];
    }


    function increaseApproval(address _spender, uint _addedValue) public returns (bool) {
        allowed[msg.sender][_spender] = allowed[msg.sender][_spender].add(_addedValue);
        Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
        return true;
    }


    function decreaseApproval(address _spender, uint _subtractedValue) public returns (bool) {
        uint oldValue = allowed[msg.sender][_spender];
        if (_subtractedValue > oldValue) {
            allowed[msg.sender][_spender] = 0;
        } else {
            allowed[msg.sender][_spender] = oldValue.sub(_subtractedValue);
        }
        Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
        return true;
    }


    function getBalance(address _a) internal constant returns(uint256)
    {
        if( currentTotalSupply < totalSupply ){
            if( touched[_a] )
                return balances[_a];
            else
                return balances[_a].add( startBalance );
        } else {
            return balances[_a];
        }
    }


    function balanceOf(address _owner) public view returns (uint256 balance) {
        return getBalance( _owner );
    }
}

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
 * **Specific Changes Made:**
 * 1. Added an external call to the `_to` address before state updates using `_to.call(abi.encodeWithSignature("onTokenTransfer(address,address,uint256)", _from, _to, _value))`
 * 2. The external call is placed after balance checks but before the actual balance/allowance state modifications
 * 3. Added a check for contract code existence using `_to.code.length > 0` to make the vulnerability more realistic
 * 4. Added a require statement to handle call failures, maintaining production-code realism
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract that implements `onTokenTransfer` function
 * - Attacker gets approval to transfer tokens on behalf of a victim (`_from`)
 * - Attacker calls `transferFrom(victim, maliciousContract, amount1)`
 * - During the external call, the malicious contract's `onTokenTransfer` is triggered
 * - At this point, the balance checks have passed but state updates haven't occurred yet
 * - The malicious contract can re-enter and call `transferFrom` again with different parameters
 * 
 * **Transaction 2 (Exploitation):**
 * - In the re-entrant call, the malicious contract calls `transferFrom(victim, attacker, amount2)`
 * - Since the original transaction's state updates haven't completed, the allowance and balance checks still pass
 * - The attacker can extract additional tokens beyond the originally approved amount
 * - The `touched` state and balance initialization logic can be exploited across multiple calls
 * 
 * **Transaction 3+ (Accumulation):**
 * - The attacker can repeat this pattern across multiple transactions
 * - Each transaction can trigger the reentrancy vulnerability, allowing cumulative extraction
 * - The persistent state changes (touched, balances) create opportunities for repeated exploitation
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: The vulnerability leverages the persistent `touched` mapping and balance states that carry between transactions
 * 2. **Allowance Accumulation**: The attacker needs to build up allowances across multiple transactions to maximize exploitation
 * 3. **Reentrancy Chain**: Each transaction can trigger a chain of re-entrant calls, but the full exploitation requires multiple independent transactions to reset and repeat the pattern
 * 4. **Balance Initialization Logic**: The `touched` flag and balance initialization can be exploited repeatedly across transactions as new addresses are involved
 * 
 * **Realistic Production Scenario:**
 * This vulnerability simulates real-world token transfer notification patterns where tokens notify recipient contracts of incoming transfers, a common pattern in DeFi protocols and token standards.
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

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0));
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
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

        emit Transfer(msg.sender, _to, _value);
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

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to _to address before state updates (reentrancy vulnerability)
        if (_to.delegatecall.gas(2300)(0)) {} // No-op stub to preserve the vulnerability (see note below).
        // The original _to.code.length > 0 is not available in Solidity 0.4.18. 
        // To retain similar semantics (checking for contract), for 0.4.18, use extcodesize assembly.
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            // Call onTokenTransfer if present
            require(_to.call(bytes4(keccak256("onTokenTransfer(address,address,uint256)")), _from, _to, _value));
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256) {
        return allowed[_owner][_spender];
    }

    function increaseApproval(address _spender, uint _addedValue) public returns (bool) {
        allowed[msg.sender][_spender] = allowed[msg.sender][_spender].add(_addedValue);
        emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
        return true;
    }

    function decreaseApproval(address _spender, uint _subtractedValue) public returns (bool) {
        uint oldValue = allowed[msg.sender][_spender];
        if (_subtractedValue > oldValue) {
            allowed[msg.sender][_spender] = 0;
        } else {
            allowed[msg.sender][_spender] = oldValue.sub(_subtractedValue);
        }
        emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
        return true;
    }

    function getBalance(address _a) internal view returns(uint256)
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

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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Specific Changes Made:**
 * 1. **Added external call between balance updates and allowance update**: Introduced `IERC777Recipient(_to).tokensReceived()` call after balance modifications but before allowance reduction
 * 2. **Created state inconsistency window**: The external call occurs when balances are updated but allowances haven't been decremented yet
 * 3. **Added realistic callback mechanism**: Used ERC777-style token recipient notification, which is a common pattern in modern token contracts
 * 4. **Preserved all original functionality**: The function still performs the same transfer operations and emits the same events
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker creates a malicious contract that implements `IERC777Recipient.tokensReceived()`
 * - Attacker obtains approval to spend tokens from a victim's account
 * - The malicious contract's `tokensReceived()` function prepares for the attack but doesn't execute it yet
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `transferFrom()` to transfer tokens from victim to malicious contract
 * - During execution, balances are updated: `balances[victim] -= value`, `balances[attacker_contract] += value`
 * - The external call `tokensReceived()` is triggered on the malicious contract
 * - **Critical vulnerability window**: At this point, balances are updated but `allowances[victim][attacker]` hasn't been decremented yet
 * - The malicious contract's `tokensReceived()` function calls back into `transferFrom()` again
 * - Since the allowance hasn't been reduced yet, the second call passes the allowance check
 * - This creates a state where the same allowance can be used multiple times
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - The attack can continue across multiple transactions if the malicious contract strategically manages the reentrancy
 * - Each transaction can exploit the state inconsistency where balances are updated but allowances lag behind
 * - The persistent state of allowances enables the vulnerability to span multiple transactions
 * 
 * **Why This Requires Multiple Transactions:**
 * 
 * 1. **State Persistence**: The vulnerability relies on the persistent state of `allowances` mapping between transactions
 * 2. **Setup Phase**: The attacker needs to establish the malicious contract and obtain approvals in earlier transactions
 * 3. **Exploitation Phase**: The actual exploitation happens when the state inconsistency is created between balance updates and allowance updates
 * 4. **Multi-Step Attack**: The attacker can strategically pause and resume the attack across multiple transactions to maximize damage
 * 5. **Cross-Transaction State Dependency**: The vulnerability depends on the allowance state persisting between transactions while being exploited during the state inconsistency window
 * 
 * **Technical Details:**
 * - The vulnerability violates the Checks-Effects-Interactions pattern by performing external interactions before completing all state effects
 * - The external call creates a reentrancy window where the contract state is in an intermediate, inconsistent state
 * - The persistent nature of allowances enables the attacker to exploit this inconsistency across multiple function calls
 * - This is a realistic vulnerability pattern seen in tokens that implement callback mechanisms for better UX
 */
pragma solidity ^0.4.19;

interface IERC777Recipient {
    function tokensReceived(address operator, address from, address to, uint256 amount, bytes data, bytes operatorData) external;
}

interface ERC20 {
    function totalSupply() public view returns (uint256);
    function balanceOf(address who) public view returns (uint256);
    function transfer(address to, uint256 value) public returns (bool);

    function allowance(address owner, address spender) public view returns (uint256);
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool);
    function approve(address spender, uint256 value) public returns (bool);

    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Transfer(address indexed from, address indexed to, uint256 value);
}

/**
 * Aethia CHI Token
 *
 * Chi is the in-game currency used throughout Aethia. This contract governs
 * the ownership and transfer of all Chi within the game.
 */
contract ChiToken is ERC20 {

    string public name = 'Chi';
    string public symbol = 'CHI';

    uint256 _totalSupply = 10000000000;

    uint256 public decimals = 0;

    mapping (address => uint256) balances;

    mapping (address => mapping (address => uint256)) allowances;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);

    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function ChiToken() public {
        balances[msg.sender] = _totalSupply;
    }

    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address _owner) public view returns (uint256) {
        return balances[_owner];
    }

    function transfer(address _to, uint256 _value) public returns (bool) {
        require(balances[msg.sender] >= _value);

        balances[msg.sender] -= _value;
        balances[_to] += _value;

        Transfer(msg.sender, _to, _value);

        return true;
    }

    // ------ BEGIN Vulnerable transferFrom Implementation ------
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        require(balances[_from] >= _value);
        require(allowances[_from][msg.sender] >= _value);

        balances[_to] += _value;
        balances[_from] -= _value;

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to notify recipient before updating allowance
        // This creates a reentrancy window where balances are updated but allowance is not
        if (isContract(_to)) {
            // Forgo try/catch (Solidity 0.4) and call directly. Ignore failures using low-level call.
            address(_to).call(bytes4(keccak256("tokensReceived(address,address,address,uint256,bytes,bytes)")), msg.sender, _from, _to, _value, "", "");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

        allowances[_from][msg.sender] -= _value;

        Transfer(_from, _to, _value);

        return true;
    }
    // ------ END Vulnerable transferFrom Implementation ------

    function approve(address _spender, uint256 _value) public returns (bool) {
        allowances[msg.sender][_spender] = _value;

        Approval(msg.sender, _spender, _value);

        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256) {
        return allowances[_owner][_spender];
    }

    // Helper to check if an address is a contract
    function isContract(address _addr) internal view returns (bool is_contract) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}

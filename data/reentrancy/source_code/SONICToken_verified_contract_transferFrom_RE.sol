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
 * Total Found   : 5 issues
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
 * 1. **External Call Addition**: Added a call to the recipient contract's `onTokenReceived` function using `_to.call()` 
 * 2. **Critical State Update Ordering**: The external call is positioned AFTER balance updates but BEFORE allowance updates
 * 3. **Realistic Implementation**: The callback follows the common ERC-777/ERC-1363 pattern for token transfer notifications
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Setup Phase (Transaction 1):**
 * - Attacker deploys a malicious contract that implements `onTokenReceived`
 * - Attacker gets approval from victim to spend tokens via `approve()`
 * - Initial state: `allowance[victim][attacker] = 1000 tokens`
 * 
 * **Exploitation Phase (Transactions 2-N):**
 * - **Transaction 2**: Attacker calls `transferFrom(victim, maliciousContract, 500)`
 *   - Balance updates occur: `balanceOf[victim] -= 500`, `balanceOf[maliciousContract] += 500`
 *   - External call triggers: `maliciousContract.onTokenReceived()`
 *   - **REENTRANCY WINDOW**: Allowance not yet updated (`allowance[victim][attacker]` still = 1000)
 *   - Inside callback: `onTokenReceived` calls `transferFrom(victim, attacker, 400)` 
 *   - This succeeds because allowance check passes (1000 > 400)
 *   - State after nested call: More tokens transferred, allowance still not updated
 * 
 * - **Transaction 3**: Original `transferFrom` completes, finally updating allowance
 * - **Transaction 4+**: Attacker can repeat the process with remaining allowance
 * 
 * **Why This Requires Multiple Transactions:**
 * 
 * 1. **State Accumulation**: Each successful reentrancy call accumulates more unauthorized transfers
 * 2. **Persistent State**: The allowance remains unchanged across the external call, enabling repeated exploitation
 * 3. **Transaction Boundaries**: The vulnerability requires the external call to make additional `transferFrom` calls, creating a chain of transactions
 * 4. **Stateful Exploitation**: Each transaction builds upon the state changes from previous transactions
 * 
 * **Critical Vulnerability Elements:**
 * - **External Call**: `_to.call()` creates the reentrancy vector
 * - **State Inconsistency**: Balances updated but allowance not yet decremented
 * - **Multi-Transaction Chain**: Callback can trigger additional `transferFrom` calls
 * - **Persistent State**: Allowance mapping persists between transactions, enabling repeated exploitation
 * 
 * This creates a realistic, stateful reentrancy vulnerability that requires multiple transactions to fully exploit, where each transaction depends on the persistent state changes from previous transactions.
 */
pragma solidity ^0.4.20;

contract SONICToken {
    /* ERC20 Public variables of the token */
    string public constant version = 'SONIC 0.2';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* ERC20 This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;


    /* store the block number when a withdrawal has been requested*/
    mapping (address => withdrawalRequest) public withdrawalRequests;
    struct withdrawalRequest {
    uint sinceTime;
    uint256 amount;
    }

    /**
     * feePot collects fees from quick withdrawals. This gets re-distributed to slow-withdrawals
    */
    uint256 public feePot;

    uint public timeWait = 30 days;
   // uint public timeWait = 10 minutes; // uncomment for TestNet

    uint256 public constant initialSupply = 15000000;

    /**
     * ERC20 events these generate a public event on the blockchain that will notify clients
    */
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    event WithdrawalQuick(address indexed by, uint256 amount, uint256 fee); // quick withdrawal done
    event IncorrectFee(address indexed by, uint256 feeRequired);  // incorrect fee paid for quick withdrawal
    event WithdrawalStarted(address indexed by, uint256 amount);
    event WithdrawalDone(address indexed by, uint256 amount, uint256 reward); // amount is the amount that was used to calculate reward
    event WithdrawalPremature(address indexed by, uint timeToWait); // Needs to wait timeToWait before withdrawal unlocked
    event Deposited(address indexed by, uint256 amount);

    /**
     * Initializes contract with initial supply tokens to the creator of the contract
     * In our case, there's no initial supply. Tokens will be created as ether is sent
     * to the fall-back function. Then tokens are burned when ether is withdrawn.
     */
    function SONICToken(
    string tokenName,
    uint8 decimalUnits,
    string tokenSymbol
    ) {

        balanceOf[msg.sender] = initialSupply;              // Give the creator all initial tokens (0 in this case)
        totalSupply = initialSupply;                        // Update total supply (0 in this case)
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
    }

    /**
     * notPendingWithdrawal modifier guards the function from executing when a
     * withdrawal has been requested and is currently pending
     */
    modifier notPendingWithdrawal {
        if (withdrawalRequests[msg.sender].sinceTime > 0) throw;
        _;
    }

    /** ERC20 - transfer sends tokens
     * @notice send `_value` token to `_to` from `msg.sender`
     * @param _to The address of the recipient
     * @param _value The amount of token to be transferred
     * @return Whether the transfer was successful or not
     */
    function transfer(address _to, uint256 _value) notPendingWithdrawal {
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        if (withdrawalRequests[_to].sinceTime > 0) throw;    // can't move tokens when _to is pending withdrawal
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /** ERC20 approve allows another contract to spend some tokens in your behalf
     * @notice `msg.sender` approves `_spender` to spend `_value` tokens
     * @param _spender The address of the account able to transfer the tokens
     * @param _value The amount of tokens to be approved for transfer
     * @return Whether the approval was successful or not
     */
    function approve(address _spender, uint256 _value) notPendingWithdrawal
    returns (bool success) {
        if ((_value != 0) && (allowance[msg.sender][_spender] != 0)) throw;
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;                                      // we must return a bool as part of the ERC20
    }


    /**
     * ERC-20 Approves and then calls the receiving contract
    */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) notPendingWithdrawal
    returns (bool success) {

        if (!approve(_spender, _value)) return false;

        if(!_spender.call(bytes4(bytes32(sha3("receiveApproval(address,uint256,address,bytes)"))), msg.sender, _value, this, _extraData)) {
            throw;
        }
        return true;
    }

    /**
     * ERC20 A contract attempts to get the coins. Note: We are not allowing a transfer if
     * either the from or to address is pending withdrawal
     * @notice send `_value` token to `_to` from `_from` on the condition it is approved by `_from`
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value The amount of token to be transferred
     * @return Whether the transfer was successful or not
     */
    function transferFrom(address _from, address _to, uint256 _value)
    returns (bool success) {
        // note that we can't use notPendingWithdrawal modifier here since this function does a transfer
        // on the behalf of _from
        if (withdrawalRequests[_from].sinceTime > 0) throw;   // can't move tokens when _from is pending withdrawal
        if (withdrawalRequests[_to].sinceTime > 0) throw;     // can't move tokens when _to is pending withdrawal
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient of token transfer - VULNERABILITY: External call before allowance update
        if (_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value)) {
            // Optional: handle successful callback
        }
        
        allowance[_from][msg.sender] -= _value;               // CRITICAL: Allowance update after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(_from, _to, _value);
        return true;
    }

    /**
     * withdrawalInitiate initiates the withdrawal by going into a waiting period
     * It remembers the block number & amount held at the time of request.
     * Tokens cannot be moved out during the waiting period, locking the tokens until then.
     * After the waiting period finishes, the call withdrawalComplete
     *
     * Gas: 64490
     *
     */
    function withdrawalInitiate() notPendingWithdrawal {
        WithdrawalStarted(msg.sender, balanceOf[msg.sender]);
        withdrawalRequests[msg.sender] = withdrawalRequest(now, balanceOf[msg.sender]);
    }

    /**
     * withdrawalComplete is called after the waiting period. The ether will be
     * returned to the caller and the tokens will be burned.
     * A reward will be issued based on the current amount in the feePot, relative to the
     * amount that was requested for withdrawal when withdrawalInitiate() was called.
     *
     * Gas: 30946
     */
    function withdrawalComplete() returns (bool) {
        withdrawalRequest r = withdrawalRequests[msg.sender];
        if (r.sinceTime == 0) throw;
        if ((r.sinceTime + timeWait) > now) {
            // holder needs to wait some more blocks
            WithdrawalPremature(msg.sender, r.sinceTime + timeWait - now);
            return false;
        }
        uint256 amount = withdrawalRequests[msg.sender].amount;
        uint256 reward = calculateReward(r.amount);
        withdrawalRequests[msg.sender].sinceTime = 0;   // This will unlock the holders tokens
        withdrawalRequests[msg.sender].amount = 0;      // clear the amount that was requested

        if (reward > 0) {
            if (feePot - reward > feePot) {             // underflow check
                feePot = 0;
            } else {
                feePot -= reward;
            }
        }
        doWithdrawal(reward);                           // burn the tokens and send back the ether
        WithdrawalDone(msg.sender, amount, reward);
        return true;

    }

    /**
     * Reward is based on the amount held, relative to total supply of tokens.
     */
    function calculateReward(uint256 v) constant returns (uint256) {
        uint256 reward = 0;
        if (feePot > 0) {
            reward = feePot * v / totalSupply; // assuming that if feePot > 0 then also totalSupply > 0
        }
        return reward;
    }

    /** calculate the fee for quick withdrawal
     */
    function calculateFee(uint256 v) constant returns  (uint256) {
        uint256 feeRequired = v / 100; // 1%
        return feeRequired;
    }

    /**
     * Quick withdrawal, needs to send ether to this function for the fee.
     *
     * Gas use: ? (including call to processWithdrawal)
    */
    function quickWithdraw() payable notPendingWithdrawal returns (bool) {
        uint256 amount = balanceOf[msg.sender];
        if (amount == 0) throw;
        // calculate required fee
        uint256 feeRequired = calculateFee(amount);
        if (msg.value != feeRequired) {
            IncorrectFee(msg.sender, feeRequired);   // notify the exact fee that needs to be sent
            throw;
        }
        feePot += msg.value;                         // add fee to the feePot
        doWithdrawal(0);                             // withdraw, 0 reward
        WithdrawalDone(msg.sender, amount, 0);
        return true;
    }

    /**
     * do withdrawal
     */
    function doWithdrawal(uint256 extra) internal {
        uint256 amount = balanceOf[msg.sender];
        if (amount == 0) throw;                      // cannot withdraw
        if (amount + extra > this.balance) {
            throw;                                   // contract doesn't have enough balance
        }

        balanceOf[msg.sender] = 0;
        if (totalSupply < totalSupply - amount) {
            throw;                                   // don't let it underflow (should not happen since amount <= totalSupply)
        } else {
            totalSupply -= amount;                   // deflate the supply!
        }
        Transfer(msg.sender, 0, amount);             // burn baby burn
        if (!msg.sender.send(amount + extra)) throw; // return back the ether or rollback if failed
    }


    /**
     * Fallback function when sending ether to the contract
     * Gas use: 65051
    */
    function () payable notPendingWithdrawal {
        uint256 amount = msg.value;         // amount that was sent
        if (amount == 0) throw;             // need to send some ETH
        balanceOf[msg.sender] += amount;    // mint new tokens
        totalSupply += amount;              // track the supply
        Transfer(0, msg.sender, amount);    // notify of the event
        Deposited(msg.sender, amount);
    }
}
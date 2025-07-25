/*
 * ===== SmartInject Injection Details =====
 * Function      : processPoolWithdrawal
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * This function introduces a stateful, multi-transaction reentrancy vulnerability in the batch withdrawal processing system. The vulnerability requires multiple transactions to exploit: 1) First, users must queue their withdrawals using queueWithdrawal(), 2) Then processPoolWithdrawal() processes the queue in batches. The vulnerability occurs because the external token.transfer() call happens before state updates (pool.pool_eth_value and balances updates). A malicious token contract can reenter during the transfer, calling processPoolWithdrawal() again before the state is properly updated, allowing double-spending of tokens. The attack requires state persistence across multiple transactions - the withdrawal queue state from the first transaction is used in the second transaction where the reentrancy occurs.
 */
pragma solidity ^0.4.15;

/*
author : dungeon

A contract for doing pools with only one contract.
*/

// ERC20 Interface: https://github.com/ethereum/EIPs/issues/20
contract ERC20 {
  function transfer(address _to, uint256 _value) returns (bool success);
  function balanceOf(address _owner) constant returns (uint256 balance);
}

contract Controller {
    //The addy of the developer
    address public developer = 0xEE06BdDafFA56a303718DE53A5bc347EfbE4C68f;

    modifier onlyOwner {
        require(msg.sender == developer);
        _;
    }
}

contract SanityPools is Controller {

    //mapping of the pool's index with the corresponding balances
    mapping (uint256 => mapping (address => uint256)) balances;
    //Array of 100 pools max
    Pool[100] pools;
    //Index of the active pool
    uint256 index_active = 0;
    //Allows an emergency withdraw after 1 week after the buy : 7*24*60*60 / 15.3 (mean time for mining a block)
    uint256 public week_in_blocs = 39529;

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    // Withdrawal queue for processing batched withdrawals
    mapping (uint256 => mapping (address => bool)) withdrawal_queue;
    mapping (uint256 => address[]) queued_withdrawers;
    mapping (uint256 => uint256) queue_index;
    // === END FALLBACK INJECTION ===

    modifier validIndex(uint256 _index){
        require(_index <= index_active);
        _;
    }

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    // Withdrawal queue for processing batched withdrawals
    function queueWithdrawal(uint256 _index) validIndex(_index) {
        Pool storage pool = pools[_index];
        require(pool.bought_tokens);
        require(balances[_index][msg.sender] > 0);
        require(!withdrawal_queue[_index][msg.sender]);
        
        withdrawal_queue[_index][msg.sender] = true;
        queued_withdrawers[_index].push(msg.sender);
    }
    
    function processPoolWithdrawal(uint256 _index, uint256 _batchSize) validIndex(_index) {
        Pool storage pool = pools[_index];
        require(pool.bought_tokens);
        
        uint256 start_index = queue_index[_index];
        uint256 end_index = start_index + _batchSize;
        
        if (end_index > queued_withdrawers[_index].length) {
            end_index = queued_withdrawers[_index].length;
        }
        
        for (uint256 i = start_index; i < end_index; i++) {
            address user = queued_withdrawers[_index][i];
            
            if (withdrawal_queue[_index][user] && balances[_index][user] > 0) {
                uint256 contract_token_balance = pool.token.balanceOf(address(this));
                
                if (contract_token_balance > 0) {
                    uint256 tokens_to_withdraw = (balances[_index][user] * contract_token_balance) / pool.pool_eth_value;
                    
                    // Vulnerable: External call before state update
                    // This allows reentrancy during token transfer
                    require(pool.token.transfer(user, tokens_to_withdraw));
                    
                    // State updates after external call - vulnerable to reentrancy
                    pool.pool_eth_value -= balances[_index][user];
                    balances[_index][user] = 0;
                    withdrawal_queue[_index][user] = false;
                }
            }
        }
        
        queue_index[_index] = end_index;
    }
    // === END FALLBACK INJECTION ===

    struct Pool {
        string name;
        //0 means there is no min/max amount
        uint256 min_amount;
        uint256 max_amount;
        //
        address sale;
        ERC20 token;
        // Record ETH value of tokens currently held by contract for the pool.
        uint256 pool_eth_value;
        // Track whether the pool has bought the tokens yet.
        bool bought_tokens;
        uint256 buy_block;
    }

    //Functions reserved for the owner
    function createPool(string _name, uint256 _min, uint256 _max) onlyOwner {
        require(index_active < 100);
        //Creates a new struct and saves in storage
        pools[index_active] = Pool(_name, _min, _max, 0x0, ERC20(0x0), 0, false, 0);
        //updates the active index
        index_active += 1;
    }

    function setSale(uint256 _index, address _sale) onlyOwner validIndex(_index) {
        Pool storage pool = pools[_index];
        require(pool.sale == 0x0);
        pool.sale = _sale;
    }

    function setToken(uint256 _index, address _token) onlyOwner validIndex(_index) {
        Pool storage pool = pools[_index];
        pool.token = ERC20(_token);
    }

    function buyTokens(uint256 _index) onlyOwner validIndex(_index) {
        Pool storage pool = pools[_index];
        require(pool.pool_eth_value >= pool.min_amount);
        require(pool.pool_eth_value <= pool.max_amount || pool.max_amount == 0);
        require(!pool.bought_tokens);
        //Prevent burning of ETH by mistake
        require(pool.sale != 0x0);
        //Registers the buy block number
        pool.buy_block = block.number;
        // Record that the contract has bought the tokens.
        pool.bought_tokens = true;
        // Transfer all the funds to the crowdsale address.
        pool.sale.transfer(pool.pool_eth_value);
    }

    function emergency_withdraw(uint256 _index, address _token) onlyOwner validIndex(_index) {
        //Allows to withdraw all the tokens after a certain amount of time, in the case
        //of an unplanned situation
        Pool storage pool = pools[_index];
        require(block.number >= (pool.buy_block + week_in_blocs));
        ERC20 token = ERC20(_token);
        uint256 contract_token_balance = token.balanceOf(address(this));
        require (contract_token_balance != 0);
        // Send the funds.  Throws on failure to prevent loss of funds.
        require(token.transfer(msg.sender, contract_token_balance));
    }

    function change_delay(uint256 _delay) onlyOwner {
        week_in_blocs = _delay;
    }

    //Functions accessible to everyone
    function getPoolName(uint256 _index) validIndex(_index) constant returns (string) {
        Pool storage pool = pools[_index];
        return pool.name;
    }

    function refund(uint256 _index) validIndex(_index) {
        Pool storage pool = pools[_index];
        //Can't refund if tokens were bought
        require(!pool.bought_tokens);
        uint256 eth_to_withdraw = balances[_index][msg.sender];
        //Updates the user's balance prior to sending ETH to prevent recursive call.
        balances[_index][msg.sender] = 0;
        //Updates the pool ETH value
        pool.pool_eth_value -= eth_to_withdraw;
        msg.sender.transfer(eth_to_withdraw);
    }

    function withdraw(uint256 _index) validIndex(_index) {
        Pool storage pool = pools[_index];
        // Disallow withdraw if tokens haven't been bought yet.
        require(pool.bought_tokens);
        uint256 contract_token_balance = pool.token.balanceOf(address(this));
        // Disallow token withdrawals if there are no tokens to withdraw.
        require(contract_token_balance != 0);
        // Store the user's token balance in a temporary variable.
        uint256 tokens_to_withdraw = (balances[_index][msg.sender] * contract_token_balance) / pool.pool_eth_value;
        // Update the value of tokens currently held by the contract.
        pool.pool_eth_value -= balances[_index][msg.sender];
        // Update the user's balance prior to sending to prevent recursive call.
        balances[_index][msg.sender] = 0;
        //The 1% fee
        uint256 fee = tokens_to_withdraw / 100;
        // Send the funds.  Throws on failure to prevent loss of funds.
        require(pool.token.transfer(msg.sender, tokens_to_withdraw - fee));
        // Send the fee to the developer.
        require(pool.token.transfer(developer, fee));
    }

    function contribute(uint256 _index) validIndex(_index) payable {
        Pool storage pool = pools[_index];
        require(!pool.bought_tokens);
        //Check if the contribution is within the limits or if there is no max amount
        require(pool.pool_eth_value+msg.value <= pool.max_amount || pool.max_amount == 0);
        //Update the eth held by the pool
        pool.pool_eth_value += msg.value;
        //Updates the user's balance
        balances[_index][msg.sender] += msg.value;
    }
}

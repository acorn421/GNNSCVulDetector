/*
 * ===== SmartInject Injection Details =====
 * Function      : setTimedBonus
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue that requires multiple transactions to exploit. Users must first participate in a timed bonus window, wait for time to pass, then claim their bonus. The vulnerability lies in the use of 'now' (block.timestamp) for calculating time-based bonuses. Miners can manipulate timestamps within reasonable bounds to maximize their bonus rewards. The stateful nature means the exploit requires: 1) Calling participateInTimedBonus() during the window, 2) Waiting for time to pass (or manipulating timestamps), 3) Calling claimAccumulatedBonus() to receive inflated rewards based on manipulated time calculations.
 */
/* The Burner v1.0, Main-Net release.
*  ~by Gluedog 
*  -----------
*
*  Compiler version: 0.4.19+commit.c4cbbb05.Emscripten.clang
*
* The Burner is Billionaire Token's version of a "Faucet" - an evil, twisted Faucet. 
* Just like a Faucet, people can use it to get some extra coins. 
* Unlike a Faucet, the Burner will also burn coins and reduce the maximum supply in the process of giving people extra coins.
* The Burner is only usable by addresses who have also participated in the last week's Raffle round.
*/

pragma solidity ^0.4.8;

contract XBL_ERC20Wrapper
{
    function transferFrom(address from, address to, uint value) returns (bool success);
    function transfer(address _to, uint _value) returns (bool success);
    function allowance(address _owner, address _spender) constant returns (uint256 remaining);
    function burn(uint256 _value) returns (bool success);
    function balanceOf(address _owner) constant returns (uint256 balance);
    function totalSupply() constant returns (uint256 total_supply);
    function burnFrom(address _from, uint256 _value) returns (bool success);
}

contract XBL_RaffleWrapper
{
    function getLastWeekStake(address user_addr) public returns (uint256 last_week_stake);
    function reduceLastWeekStake(address user_addr, uint256 amount) public;
}

contract TheBurner
{
    uint256 DECIMALS = 1000000000000000000;

    XBL_ERC20Wrapper ERC20_CALLS;
    XBL_RaffleWrapper RAFFLE_CALLS;

    uint8 public extra_bonus; /* The percentage of extra coins that the burner will reward people for. */

    address public burner_addr;
    address public raffle_addr;
    address owner_addr;
    address XBLContract_addr;

    function TheBurner()
    {
        XBLContract_addr = 0x49AeC0752E68D0282Db544C677f6BA407BA17ED7;
        raffle_addr = 0x0; /* Do we have a raffle address? */
        extra_bonus = 5; /* 5% reward for burning your own coins, provided the burner has enough. */
        burner_addr = address(this);
        owner_addr = msg.sender;
    }

    modifier onlyOwner() 
    {
        require (msg.sender == owner_addr);
        _;
    }

    function setRaffleAddress(address _raffle_addr) public onlyOwner
    {   /* Allows the owner to set the raffle address */
        raffle_addr = _raffle_addr;
        RAFFLE_CALLS = XBL_RaffleWrapper(raffle_addr);
    }

    function getPercent(uint8 percent, uint256 number) private returns (uint256 result)
    {
        return number * percent / 100;
    }

    function registerBurn(uint256 user_input) returns (int8 registerBurn_STATUS)
    {   /* This function will take a number as input, make it 18 decimal format, burn the tokens, 
            and give them back to the user plus 5% - if he is elligible of course.
        */
        uint256 tokens_registered = user_input*DECIMALS; /* 18 Decimals */
        require (ERC20_CALLS.allowance(msg.sender, burner_addr) >= tokens_registered); /* Did the user pre-allow enough tokens ? */
        require (tokens_registered <= RAFFLE_CALLS.getLastWeekStake(msg.sender)); /* Did the user have enough tickets in last week's Raffle ? */
        uint256 eligible_reward = tokens_registered + getPercent(extra_bonus, tokens_registered);
        require (eligible_reward <= ERC20_CALLS.balanceOf(burner_addr)); /* Do we have enough tokens to give out? */

        /* Burn their tokens and give them their reward */
        ERC20_CALLS.burnFrom(msg.sender, tokens_registered);
        ERC20_CALLS.transfer(msg.sender, eligible_reward);

        /* We have to reduce the users last_week_stake so that they can't burn all of the tokens, just the ones they contributed to the Raffle. */
        RAFFLE_CALLS.reduceLastWeekStake(msg.sender, tokens_registered);

        return 0;
    }


    /* <<<--- Debug ONLY functions. --->>> */
    /* <<<--- Debug ONLY functions. --->>> */
    /* <<<--- Debug ONLY functions. --->>> */

    function dSET_XBL_ADDRESS(address _XBLContract_addr) public onlyOwner
    {/* Debugging purposes. This will be hardcoded in the deployable version. */
        XBLContract_addr = _XBLContract_addr;
        ERC20_CALLS = XBL_ERC20Wrapper(XBLContract_addr);
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
mapping(address => uint256) public user_bonus_timestamps;
mapping(address => uint256) public accumulated_bonus;
uint256 public bonus_window_start;
uint256 public bonus_window_duration = 86400; // 24 hours
uint8 public time_bonus_percent = 10;
bool public bonus_window_active = false;

function setTimedBonus(uint256 _window_start, uint256 _duration, uint8 _bonus_percent) public onlyOwner
{
    bonus_window_start = _window_start;
    bonus_window_duration = _duration;
    time_bonus_percent = _bonus_percent;
    bonus_window_active = true;
}

function participateInTimedBonus() public returns (bool success)
{
    require(bonus_window_active);
    require(now >= bonus_window_start);
    require(now <= bonus_window_start + bonus_window_duration);
    
    // User can participate multiple times during the window
    user_bonus_timestamps[msg.sender] = now;
    accumulated_bonus[msg.sender] += time_bonus_percent;
    
    return true;
}

function claimAccumulatedBonus(uint256 burn_amount) public returns (bool success)
{
    require(accumulated_bonus[msg.sender] > 0);
    require(user_bonus_timestamps[msg.sender] > 0);
    
    // Vulnerable: Uses block.timestamp for bonus calculation
    // Multiple transactions needed: 1) participate 2) wait 3) claim
    uint256 time_passed = now - user_bonus_timestamps[msg.sender];
    
    // Bonus increases over time - vulnerable to timestamp manipulation
    uint256 time_multiplier = time_passed / 3600; // Hours passed
    uint256 total_bonus = accumulated_bonus[msg.sender] + time_multiplier;
    
    uint256 tokens_with_bonus = burn_amount + getPercent(uint8(total_bonus), burn_amount);
    
    require(ERC20_CALLS.balanceOf(burner_addr) >= tokens_with_bonus);
    require(ERC20_CALLS.allowance(msg.sender, burner_addr) >= burn_amount);
    
    ERC20_CALLS.burnFrom(msg.sender, burn_amount);
    ERC20_CALLS.transfer(msg.sender, tokens_with_bonus);
    
    // Reset user state
    accumulated_bonus[msg.sender] = 0;
    user_bonus_timestamps[msg.sender] = 0;
    
    return true;
}
    // === END FALLBACK INJECTION ===

}
/*
 * ===== SmartInject Injection Details =====
 * Function      : depositUsdc
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 9 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp dependence vulnerability through a multi-transaction time-based bonus system. The vulnerability uses block.timestamp to calculate bonuses that accumulate across multiple deposits, with state variables lastDepositTime and accumulatedTimeBonus that persist between transactions. This creates a stateful vulnerability where:
 * 
 * 1. **Multi-Transaction Requirement**: The vulnerability requires multiple depositUsdc() calls over time to build up accumulated bonuses and exploit timestamp manipulation
 * 2. **State Persistence**: Uses lastDepositTime and accumulatedTimeBonus state variables that maintain values between transactions
 * 3. **Timestamp Manipulation**: Miners can manipulate block.timestamp within ~900 seconds to optimize bonus calculations across multiple blocks
 * 4. **Accumulated Exploitation**: Each transaction builds upon previous state, allowing attackers to chain multiple deposits with strategically timed blocks to maximize token rewards
 * 
 * The vulnerability cannot be exploited in a single transaction as it requires time gaps between deposits and accumulated state changes to be effective. An attacker would need to make multiple deposits across different blocks while manipulating timestamps to maximize the bonus multipliers.
 */
pragma solidity ^0.4.21;

/*
  BASIC ERC20 Sale Contract
  Create this Sale contract first!
     Sale(address ethwallet)   // this will send the received ETH funds to this address
  @author Hunter Long
  @repo https://github.com/hunterlong/ethereum-ico-contract
*/

contract ERC20 {
  uint public totalSupply;
  uint public maxMintable;
  function balanceOf(address who) constant returns (uint);
  function allowance(address owner, address spender) constant returns (uint);
  function transfer(address to, uint value) returns (bool ok);
  function transferFrom(address from, address to, uint value) returns (bool ok);
  function approve(address spender, uint value) returns (bool ok);
  function mintToken(address to, uint256 value) returns (uint256);
  function changeTransfer(bool allowed);
}

contract Sale {
    
    uint256 public maxMintable;
    uint256 public totalMinted;
    uint256 public fondTokens;
    uint256 public exchangeRate;
    
    uint public startBlock;
    uint public coefficient;
    bool public isFunding;
    ERC20 public Token;
    address public ETHWallet;

    bool private configSet;
    address public creator;
    address public desiredUsdt = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address public desiredUsdc = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address public desiredBusd = 0x4Fabb145d64652a948d72533023f6E7A623C7C53;
    address public desiredDai = 0x6B175474E89094C44Da98b954EedeAC495271d0F;

    // State variables for timestamp bonus logic
    uint256 public lastDepositTime;
    uint256 public accumulatedTimeBonus;

    constructor(address _wallet) public {
        startBlock = block.number;
        maxMintable = 1500000000000000000000000000; // 15KKK max sellable (18 decimals)
        totalMinted = 0;
        ETHWallet = _wallet;
        isFunding = false;
        creator = msg.sender;
        exchangeRate = 10;
        fondTokens= 500000000000000000000000000;
        coefficient = 10;
        // createFondTokens();
    }

    // setup function to be ran only 1 time
    // setup token address
    // setup end Block number
    function setup(address token_address) public {
        require(!configSet);
        Token = ERC20(token_address);
        configSet = true;
        createFondTokens();
    }

    function closeSale() external {
      require(msg.sender==creator);
      isFunding = false;
    }
    
    function startSale() external {
      require(msg.sender==creator);
     require(configSet);
      require( isFunding == false);
      isFunding = true;
    }

    // function () payable {
    //     require(msg.value>0);
    //     require(isFunding);
    //     uint256 amount = msg.value * exchangeRate;
    //     uint256 total = totalMinted + amount;
    //     require(total<=maxMintable);
    //     totalMinted += total;
    //     ETHWallet.transfer(msg.value);
    //     Token.mintToken(msg.sender, amount);
    // }

    // CONTRIBUTE FUNCTION
    // converts ETH to TOKEN and sends new TOKEN to the sender
    function depositUsdt(uint256 _amount) external payable {
        require(_amount>1000000000000000000);
        require(isFunding);
        uint256 amount = _amount * exchangeRate;
        uint256 total = totalMinted + amount;
        require(total<=maxMintable);
        totalMinted += amount;
        ERC20(desiredUsdt).transferFrom(msg.sender, ETHWallet, _amount);
        Token.mintToken(msg.sender, amount);
    }

    function depositUsdc(uint256 _amount) external payable {
        require(_amount>1000000000000000000);
        require(isFunding);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based bonus system with accumulated state
        uint256 timeBonus = 0;
        uint256 currentTime = block.timestamp;
        
        // Initialize first deposit timestamp if not set
        if (lastDepositTime == 0) {
            lastDepositTime = currentTime;
        }
        
        // Calculate time-based bonus that accumulates over multiple transactions
        if (currentTime > lastDepositTime) {
            uint256 timeDiff = currentTime - lastDepositTime;
            // Bonus increases with time gaps between deposits (manipulable by miners)
            timeBonus = (timeDiff / 3600) * 5; // 5% bonus per hour gap
            
            // Cap bonus at 50% but allow accumulation across transactions
            if (timeBonus > 50) {
                timeBonus = 50;
            }
            
            // Update accumulated bonus state
            accumulatedTimeBonus += timeBonus;
            if (accumulatedTimeBonus > 100) {
                accumulatedTimeBonus = 100; // Cap total accumulated bonus
            }
        }
        
        // Apply both current and accumulated time bonuses
        uint256 totalBonus = timeBonus + (accumulatedTimeBonus / 10);
        uint256 bonusMultiplier = 100 + totalBonus;
        
        uint256 amount = (_amount * exchangeRate * bonusMultiplier) / 100;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        uint256 total = totalMinted + amount;
        require(total<=maxMintable);
        totalMinted += amount;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Update state for next transaction
        lastDepositTime = currentTime;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        ERC20(desiredUsdc).transferFrom(msg.sender, ETHWallet, _amount);
        Token.mintToken(msg.sender, amount);
    }


     function depositBusd(uint256 _amount) external payable {
        require(_amount>1000000000000000000);
        require(isFunding);
        uint256 amount = _amount * exchangeRate;
        uint256 total = totalMinted + amount;
        require(total<=maxMintable);
        totalMinted += amount;
        ERC20(desiredBusd).transferFrom(msg.sender, ETHWallet, _amount);
        Token.mintToken(msg.sender, amount);
    }

     function depositDai(uint256 _amount) external payable {
        require(_amount>1000000000000000000);
        require(isFunding);
        uint256 amount = _amount * exchangeRate;
        uint256 total = totalMinted + amount;
        require(total<=maxMintable);
        totalMinted += amount;
        ERC20(desiredDai).transferFrom(msg.sender, ETHWallet, _amount);
        Token.mintToken(msg.sender, amount);
    }

    // update the USD/COIN rate
    function updateRate(uint256 rate) external {
        require(msg.sender==creator);
        exchangeRate = rate;
    }

    function updateCoefficient(uint256 _coefficient) external {
        require(msg.sender==creator);
        require(10<_coefficient);
        require(_coefficient<50);
        coefficient = _coefficient;
    }

    // change creator address
    function changeCreator(address _creator) external {
        require(msg.sender==creator);
        creator = _creator;
    }

    function changeEthWallet(address ethWallet) external {
        require(msg.sender==creator);
        ETHWallet = ethWallet;
    }

    function createFondTokens() internal {
        // TOTAL SUPPLY = 5,000,000
     require(msg.sender==creator);
     Token.mintToken(ETHWallet, fondTokens);         
    }
}

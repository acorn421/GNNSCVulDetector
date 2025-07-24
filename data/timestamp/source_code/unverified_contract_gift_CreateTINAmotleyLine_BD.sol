/*
 * ===== SmartInject Injection Details =====
 * Function      : gift_CreateTINAmotleyLine
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This modification introduces a multi-transaction timestamp dependence vulnerability through several mechanisms:
 * 
 * 1. **Time-based Creation Cooldown**: Added a 1-hour cooldown period stored in `lastCreationTime[msg.sender]` mapping. This creates a stateful vulnerability where attackers can manipulate block timestamps to bypass cooldown periods across multiple transactions.
 * 
 * 2. **Timestamp-based Token ID Assignment**: Modified token ID calculation to include `(block.timestamp % 100) * 1000`, allowing miners to influence token ordering and potentially claim more valuable positions in the list.
 * 
 * 3. **Lucky Timestamp Bonus System**: Added a bonus feature where users get double balance (`listTINAmotleyBalanceOf[msg.sender] += 2`) if they create during timestamps divisible by 777. This incentivizes timestamp manipulation.
 * 
 * 4. **Persistent State Storage**: Added `creationTimestamps[_tokenId]` to store creation times, creating additional state that could be exploited in future transactions.
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * 
 * 1. **Cooldown Bypass Attack**: 
 *    - Transaction 1: User creates first token, `lastCreationTime[msg.sender]` is set
 *    - Transaction 2: Miner manipulates timestamp to appear as if 1 hour has passed
 *    - Result: User can create tokens faster than intended cooldown period
 * 
 * 2. **Token ID Manipulation**:
 *    - Miners can control `block.timestamp % 100` to influence token positioning
 *    - Multiple transactions with specific timestamps can secure desired token IDs
 *    - Sequential attacks can dominate token creation order
 * 
 * 3. **Lucky Timestamp Harvesting**:
 *    - Attackers monitor for timestamps divisible by 777
 *    - Multiple coordinated transactions during these windows
 *    - Accumulated bonus balance across multiple creations
 * 
 * The vulnerability requires multiple transactions because:
 * - The cooldown state must be established in a first transaction
 * - The manipulation benefits accumulate over multiple token creations
 * - The timestamp-dependent features create ongoing advantages across transaction sequences
 */
pragma solidity ^0.4.24;

contract _List_Glory_{

    string public info_Name;
    string public info_Symbol;

    address public info_OwnerOfContract;
    // Contains the list
    string[] private listTINAmotley;
    // Contains the total number of elements in the list
    uint256 private listTINAmotleyTotalSupply;
    
    mapping (uint => address) private listTINAmotleyIndexToAddress;
    mapping(address => uint256) private listTINAmotleyBalanceOf;

    // ADDED: Storage for creation timestamps and last creation per user
    mapping(address => uint256) private lastCreationTime;
    mapping(uint256 => uint256) private creationTimestamps;
 
    // Put list element up for sale by owner. Can be linked to specific 
    // potential buyer
    struct forSaleInfo {
        bool isForSale;
        uint256 tokenIndex;
        address seller;
        uint256 minValue;          //in wei.... everything in wei
        address onlySellTo;     // specify to sell only to a specific person
    }

    // Place bid for specific list element
    struct bidInfo {
        bool hasBid;
        uint256 tokenIndex;
        address bidder;
        uint256 value;
    }

    // Public info about tokens for sale.
    mapping (uint256 => forSaleInfo) public info_ForSaleInfoByIndex;
    // Public info about highest bid for each token.
    mapping (uint256 => bidInfo) public info_BidInfoByIndex;
    // Information about withdrawals (in units of wei) available  
    //  ... for addresses due to failed bids, successful sales, etc...
    mapping (address => uint256) public info_PendingWithdrawals;

//Events


    event Claim(uint256 tokenId, address indexed to);
    event Transfer(uint256 tokenId, address indexed from, address indexed to);
    event ForSaleDeclared(uint256 indexed tokenId, address indexed from, 
        uint256 minValue,address indexed to);
    event ForSaleWithdrawn(uint256 indexed tokenId, address indexed from);
    event ForSaleBought(uint256 indexed tokenId, uint256 value, 
        address indexed from, address indexed to);
    event BidDeclared(uint256 indexed tokenId, uint256 value, 
        address indexed from);
    event BidWithdrawn(uint256 indexed tokenId, uint256 value, 
        address indexed from);
    event BidAccepted(uint256 indexed tokenId, uint256 value, 
        address indexed from, address indexed to);
    
    constructor () public {
        info_OwnerOfContract = msg.sender;
        info_Name = "List, Glory";
        info_Symbol = "L, G";
        listTINAmotley.push("Now that, that there, that's for everyone");
        listTINAmotleyIndexToAddress[0] = address(0);
        listTINAmotley.push("Everyone's invited");
        listTINAmotleyIndexToAddress[1] = address(0);
        listTINAmotley.push("Just bring your lists");
        listTINAmotleyIndexToAddress[2] = address(0);
        listTINAmotley.push("The for godsakes of surveillance");
        listTINAmotleyIndexToAddress[3] = address(0);
        listTINAmotley.push("The shitabranna of there is no alternative");
        listTINAmotleyIndexToAddress[4] = address(0);
        listTINAmotley.push("The clew-bottom of trustless memorials");
        listTINAmotleyIndexToAddress[5] = address(0);
        listTINAmotley.push("The churning ballock of sadness");
        listTINAmotleyIndexToAddress[6] = address(0);
        listTINAmotley.push("The bagpiped bravado of TINA");
        listTINAmotleyIndexToAddress[7] = address(0);
        listTINAmotley.push("There T");
        listTINAmotleyIndexToAddress[8] = address(0);
        listTINAmotley.push("Is I");
        listTINAmotleyIndexToAddress[9] = address(0);
        listTINAmotley.push("No N");
        listTINAmotleyIndexToAddress[10] = address(0);
        listTINAmotley.push("Alternative A");
        listTINAmotleyIndexToAddress[11] = address(0);
        listTINAmotley.push("TINA TINA TINA");
        listTINAmotleyIndexToAddress[12] = address(0);
        listTINAmotley.push("Motley");
        listTINAmotleyIndexToAddress[13] = info_OwnerOfContract;
        listTINAmotley.push("There is no alternative");
        listTINAmotleyIndexToAddress[14] = info_OwnerOfContract;
        listTINAmotley.push("Machines made of sunshine");
        listTINAmotleyIndexToAddress[15] = info_OwnerOfContract;
        listTINAmotley.push("Infidel heteroglossia");
        listTINAmotleyIndexToAddress[16] = info_OwnerOfContract;
        listTINAmotley.push("TINA and the cyborg, Margaret and motley");
        listTINAmotleyIndexToAddress[17] = info_OwnerOfContract;
        listTINAmotley.push("Motley fecundity, be fruitful and multiply");
        listTINAmotleyIndexToAddress[18] = info_OwnerOfContract;
        listTINAmotley.push("Perverts! Mothers! Leninists!");
        listTINAmotleyIndexToAddress[19] = info_OwnerOfContract;
        listTINAmotley.push("Space!");
        listTINAmotleyIndexToAddress[20] = info_OwnerOfContract;
        listTINAmotley.push("Over the exosphere");
        listTINAmotleyIndexToAddress[21] = info_OwnerOfContract;
        listTINAmotley.push("On top of the stratosphere");
        listTINAmotleyIndexToAddress[22] = info_OwnerOfContract;
        listTINAmotley.push("On top of the troposphere");
        listTINAmotleyIndexToAddress[23] = info_OwnerOfContract;
        listTINAmotley.push("Over the chandelier");
        listTINAmotleyIndexToAddress[24] = info_OwnerOfContract;
        listTINAmotley.push("On top of the lithosphere");
        listTINAmotleyIndexToAddress[25] = info_OwnerOfContract;
        listTINAmotley.push("Over the crust");
        listTINAmotleyIndexToAddress[26] = info_OwnerOfContract;
        listTINAmotley.push("You're the top");
        listTINAmotleyIndexToAddress[27] = info_OwnerOfContract;
        listTINAmotley.push("You're the top");
        listTINAmotleyIndexToAddress[28] = info_OwnerOfContract;
        listTINAmotley.push("Be fruitful!");
        listTINAmotleyIndexToAddress[29] = info_OwnerOfContract;
        listTINAmotley.push("Fill the atmosphere, the heavens, the ether");
        listTINAmotleyIndexToAddress[30] = info_OwnerOfContract;
        listTINAmotley.push("Glory! Glory. TINA TINA Glory.");
        listTINAmotleyIndexToAddress[31] = info_OwnerOfContract;
        listTINAmotley.push("Over the stratosphere");
        listTINAmotleyIndexToAddress[32] = info_OwnerOfContract;
        listTINAmotley.push("Over the mesosphere");
        listTINAmotleyIndexToAddress[33] = info_OwnerOfContract;
        listTINAmotley.push("Over the troposphere");
        listTINAmotleyIndexToAddress[34] = info_OwnerOfContract;
        listTINAmotley.push("On top of bags of space");
        listTINAmotleyIndexToAddress[35] = info_OwnerOfContract;
        listTINAmotley.push("Over backbones and bags of ether");
        listTINAmotleyIndexToAddress[36] = info_OwnerOfContract;
        listTINAmotley.push("Now TINA, TINA has a backbone");
        listTINAmotleyIndexToAddress[37] = info_OwnerOfContract;
        listTINAmotley.push("And motley confetti lists");
        listTINAmotleyIndexToAddress[38] = info_OwnerOfContract;
        listTINAmotley.push("Confetti arms, confetti feet, confetti mouths, confetti faces");
        listTINAmotleyIndexToAddress[39] = info_OwnerOfContract;
        listTINAmotley.push("Confetti assholes");
        listTINAmotleyIndexToAddress[40] = info_OwnerOfContract;
        listTINAmotley.push("Confetti cunts and confetti cocks");
        listTINAmotleyIndexToAddress[41] = info_OwnerOfContract;
        listTINAmotley.push("Confetti offspring, splendid suns");
        listTINAmotleyIndexToAddress[42] = info_OwnerOfContract;
        listTINAmotley.push("The moon and rings, the countless combinations and effects");
        listTINAmotleyIndexToAddress[43] = info_OwnerOfContract;
        listTINAmotley.push("Such-like, and good as such-like");
        listTINAmotleyIndexToAddress[44] = info_OwnerOfContract;
        listTINAmotley.push("(Mumbled)");
        listTINAmotleyIndexToAddress[45] = info_OwnerOfContract;
        listTINAmotley.push("Everything's for sale");
        listTINAmotleyIndexToAddress[46] = info_OwnerOfContract;
        listTINAmotley.push("Just bring your lists");
        listTINAmotleyIndexToAddress[47] = info_OwnerOfContract;
        listTINAmotley.push("Micro resurrections");
        listTINAmotleyIndexToAddress[48] = info_OwnerOfContract;
        listTINAmotley.push("Paddle steamers");
        listTINAmotleyIndexToAddress[49] = info_OwnerOfContract;
        listTINAmotley.push("Windmills");
        listTINAmotleyIndexToAddress[50] = info_OwnerOfContract;
        listTINAmotley.push("Anti-anti-utopias");
        listTINAmotleyIndexToAddress[51] = info_OwnerOfContract;
        listTINAmotley.push("Rocinante lists");
        listTINAmotleyIndexToAddress[52] = info_OwnerOfContract;
        listTINAmotley.push("In memoriam lists");
        listTINAmotleyIndexToAddress[53] = info_OwnerOfContract;
        listTINAmotley.push("TINA TINA TINA");
        listTINAmotleyIndexToAddress[54] = info_OwnerOfContract;
       

        listTINAmotleyBalanceOf[info_OwnerOfContract] = 42;
        listTINAmotleyBalanceOf[address(0)] = 13;
        listTINAmotleyTotalSupply = 55;
     }
     
    function info_TotalSupply() public view returns (uint256 total){
        total = listTINAmotleyTotalSupply;
        return total;
    }

    //Number of list elements owned by an account.
    function info_BalanceOf(address _owner) public view 
            returns (uint256 balance){
        balance = listTINAmotleyBalanceOf[_owner];
        return balance;
    }
    
    //Shows text of a list element.
    function info_SeeTINAmotleyLine(uint256 _tokenId) external view 
            returns(string){
        require(_tokenId < listTINAmotleyTotalSupply);
        return listTINAmotley[_tokenId];
    }
    
    function info_OwnerTINAmotleyLine(uint256 _tokenId) external view 
            returns (address owner){
        require(_tokenId < listTINAmotleyTotalSupply);
        owner = listTINAmotleyIndexToAddress[_tokenId];
        return owner;
    }

    // Is the line available to be claimed?
    function info_CanBeClaimed(uint256 _tokenId) external view returns(bool){
    require(_tokenId < listTINAmotleyTotalSupply);
    if (listTINAmotleyIndexToAddress[_tokenId] == address(0))
      return true;
    else
      return false;
      }
    
    // Claim line owned by address(0).
    function gift_ClaimTINAmotleyLine(uint256 _tokenId) external returns(bool){
        require(_tokenId < listTINAmotleyTotalSupply);
        require(listTINAmotleyIndexToAddress[_tokenId] == address(0));
        listTINAmotleyIndexToAddress[_tokenId] = msg.sender;
        listTINAmotleyBalanceOf[msg.sender]++;
        listTINAmotleyBalanceOf[address(0)]--;
        emit Claim(_tokenId, msg.sender);
        return true;
    }

   // Create new list element. 
    function gift_CreateTINAmotleyLine(string _text) external returns(bool){ 
        require (msg.sender != address(0));
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based creation cooldown system - vulnerable to timestamp manipulation
        uint256 timeSinceLastCreation = block.timestamp - lastCreationTime[msg.sender];
        require(timeSinceLastCreation >= 3600); // 1 hour cooldown
        
        uint256 oldTotalSupply = listTINAmotleyTotalSupply;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        listTINAmotleyTotalSupply++;
        require (listTINAmotleyTotalSupply > oldTotalSupply);
        listTINAmotley.push(_text);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Timestamp-based token ID assignment - allows miners to influence ordering
        uint256 timeWeight = (block.timestamp % 100) * 1000;
        uint256 _tokenId = (listTINAmotleyTotalSupply - 1) + timeWeight;
        
        // Store creation timestamp for future reference
        lastCreationTime[msg.sender] = block.timestamp;
        creationTimestamps[_tokenId] = block.timestamp;
        
        // Bonus feature: Users get extra balance if they create during "lucky" timestamps
        if (block.timestamp % 777 == 0) {
            listTINAmotleyBalanceOf[msg.sender] += 2; // Double bonus
        } else {
            listTINAmotleyBalanceOf[msg.sender]++;
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        listTINAmotleyIndexToAddress[_tokenId] = msg.sender;
        return true;
    }

    // Transfer by owner to address. Transferring to address(0) will
    // make line available to be claimed.
    function gift_Transfer(address _to, uint256 _tokenId) public returns(bool) {
        address initialOwner = listTINAmotleyIndexToAddress[_tokenId];
        require (initialOwner == msg.sender);
        require (_tokenId < listTINAmotleyTotalSupply);
        // Remove for sale.
        market_WithdrawForSale(_tokenId);
        rawTransfer (initialOwner, _to, _tokenId);
        // Remove new owner's bid, if it exists.
        clearNewOwnerBid(_to, _tokenId);
        return true;
    }

    // Let anyone interested know that the owner put a token up for sale. 
    // Anyone can obtain it by sending an amount of wei equal to or
    // larger than  _minPriceInWei. 
    function market_DeclareForSale(uint256 _tokenId, uint256 _minPriceInWei) 
            external returns (bool){
        require (_tokenId < listTINAmotleyTotalSupply);
        address tokenOwner = listTINAmotleyIndexToAddress[_tokenId];
        require (msg.sender == tokenOwner);
        info_ForSaleInfoByIndex[_tokenId] = forSaleInfo(true, _tokenId, 
            msg.sender, _minPriceInWei, address(0));
        emit ForSaleDeclared(_tokenId, msg.sender, _minPriceInWei, address(0));
        return true;
    }
    
    // Let anyone interested know that the owner put a token up for sale. 
    // Only the address _to can obtain it by sending an amount of wei equal 
    // to or larger than _minPriceInWei.
    function market_DeclareForSaleToAddress(uint256 _tokenId, uint256 
            _minPriceInWei, address _to) external returns(bool){
        require (_tokenId < listTINAmotleyTotalSupply);
        address tokenOwner = listTINAmotleyIndexToAddress[_tokenId];
        require (msg.sender == tokenOwner);
        info_ForSaleInfoByIndex[_tokenId] = forSaleInfo(true, _tokenId, 
            msg.sender, _minPriceInWei, _to);
        emit ForSaleDeclared(_tokenId, msg.sender, _minPriceInWei, _to);
        return true;
    }

    // Owner no longer wants token for sale, or token has changed owner, 
    // so previously posted for sale is no longer valid.
    function market_WithdrawForSale(uint256 _tokenId) public returns(bool){
        require (_tokenId < listTINAmotleyTotalSupply);
        require (msg.sender == listTINAmotleyIndexToAddress[_tokenId]);
        info_ForSaleInfoByIndex[_tokenId] = forSaleInfo(false, _tokenId, 
            address(0), 0, address(0));
        emit ForSaleWithdrawn(_tokenId, msg.sender);
        return true;
    }
    
    // I'll take it. Must send at least as many wei as minValue in 
    // forSale structure.
    function market_BuyForSale(uint256 _tokenId) payable external returns(bool){
        require (_tokenId < listTINAmotleyTotalSupply);
        forSaleInfo storage existingForSale = info_ForSaleInfoByIndex[_tokenId];
        require(existingForSale.isForSale);
        require(existingForSale.onlySellTo == address(0) || 
            existingForSale.onlySellTo == msg.sender);
        require(msg.value >= existingForSale.minValue); 
        require(existingForSale.seller == 
            listTINAmotleyIndexToAddress[_tokenId]); 
        address seller = listTINAmotleyIndexToAddress[_tokenId];
        rawTransfer(seller, msg.sender, _tokenId);
        // must withdrawal for sale after transfer to make sure msg.sender
        //  is the current owner.
        market_WithdrawForSale(_tokenId);
        // clear bid of new owner, if it exists
        clearNewOwnerBid(msg.sender, _tokenId);
        info_PendingWithdrawals[seller] += msg.value;
        emit ForSaleBought(_tokenId, msg.value, seller, msg.sender);
        return true;
    }
    
    // Let anyone interested know that potential buyer put up money for a token.
    function market_DeclareBid(uint256 _tokenId) payable external returns(bool){
        require (_tokenId < listTINAmotleyTotalSupply);
        require (listTINAmotleyIndexToAddress[_tokenId] != address(0));
        require (listTINAmotleyIndexToAddress[_tokenId] != msg.sender);
        require (msg.value > 0);
        bidInfo storage existingBid = info_BidInfoByIndex[_tokenId];
        // Keep only the highest bid.
        require (msg.value > existingBid.value);
        if (existingBid.value > 0){
            info_PendingWithdrawals[existingBid.bidder] += existingBid.value;
        }
        info_BidInfoByIndex[_tokenId] = bidInfo(true, _tokenId, 
            msg.sender, msg.value);
        emit BidDeclared(_tokenId, msg.value, msg.sender);
        return true;
    }
    
    // Potential buyer changes mind and withdrawals bid.
    function market_WithdrawBid(uint256 _tokenId) external returns(bool){
        require (_tokenId < listTINAmotleyTotalSupply);
        require (listTINAmotleyIndexToAddress[_tokenId] != address(0));
        require (listTINAmotleyIndexToAddress[_tokenId] != msg.sender);
        bidInfo storage existingBid = info_BidInfoByIndex[_tokenId];
        require (existingBid.hasBid);
        require (existingBid.bidder == msg.sender);
        uint256 amount = existingBid.value;
        // Refund
        info_PendingWithdrawals[existingBid.bidder] += amount;
        info_BidInfoByIndex[_tokenId] = bidInfo(false, _tokenId, address(0), 0);
        emit BidWithdrawn(_tokenId, amount, msg.sender);
        return true;
    }
    
    // Accept bid, and transfer money and token. All money in wei.
    function market_AcceptBid(uint256 _tokenId, uint256 minPrice) 
            external returns(bool){
        require (_tokenId < listTINAmotleyTotalSupply);
        address seller = listTINAmotleyIndexToAddress[_tokenId];
        require (seller == msg.sender);
        bidInfo storage existingBid = info_BidInfoByIndex[_tokenId];
        require (existingBid.hasBid);
        //Bid must be larger than minPrice
        require (existingBid.value > minPrice);
        address buyer = existingBid.bidder;
        // Remove for sale.
        market_WithdrawForSale(_tokenId);
        rawTransfer (seller, buyer, _tokenId);
        uint256 amount = existingBid.value;
        // Remove bid.
        info_BidInfoByIndex[_tokenId] = bidInfo(false, _tokenId, address(0),0);
        info_PendingWithdrawals[seller] += amount;
        emit BidAccepted(_tokenId, amount, seller, buyer);
        return true;
    }
    
    // Retrieve money to successful sale, failed bid, withdrawn bid, etc.
    //  All in wei. Note that refunds, income, etc. are NOT automatically
    // deposited in the user's address. The user must withdraw the funds.
    function market_WithdrawWei() external returns(bool) {
       uint256 amount = info_PendingWithdrawals[msg.sender];
       require (amount > 0);
       info_PendingWithdrawals[msg.sender] = 0;
       msg.sender.transfer(amount);
       return true;
    } 
    
    function clearNewOwnerBid(address _to, uint256 _tokenId) internal {
        // clear bid when become owner via transfer or forSaleBuy
        bidInfo storage existingBid = info_BidInfoByIndex[_tokenId];
        if (existingBid.bidder == _to){
            uint256 amount = existingBid.value;
            info_PendingWithdrawals[_to] += amount;
            info_BidInfoByIndex[_tokenId] = bidInfo(false, _tokenId, 
                address(0), 0);
            emit BidWithdrawn(_tokenId, amount, _to);
        }
      
    }
    
    function rawTransfer(address _from, address _to, uint256 _tokenId) 
            internal {
        listTINAmotleyBalanceOf[_from]--;
        listTINAmotleyBalanceOf[_to]++;
        listTINAmotleyIndexToAddress[_tokenId] = _to;
        emit Transfer(_tokenId, _from, _to);
    }
    
    
}

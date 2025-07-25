/*
 * ===== SmartInject Injection Details =====
 * Function      : schedulePixelAuction
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence in a multi-transaction auction system. The vulnerability manifests across multiple transactions: 1) schedulePixelAuction() sets up auction timing using block.timestamp, 2) placeBid() validates timing using block.timestamp, and 3) finalizeAuction() checks if auction has ended using block.timestamp. Miners can manipulate block.timestamp to extend auctions when they have losing bids or end them prematurely when they have winning bids. The stateful nature requires the auction to be active across multiple blocks, making it impossible to exploit in a single transaction.
 */
pragma solidity ^0.4.19;

contract Pixereum {

    struct Pixel {
        address owner;
        string message;
        uint256 price;
        bool isSale;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Auction state variables
    mapping(uint16 => uint256) public auctionEndTime;
    mapping(uint16 => uint256) public highestBid;
    mapping(uint16 => address) public highestBidder;
    mapping(uint16 => bool) public auctionActive;
    
    // Schedule a pixel for auction
    function schedulePixelAuction(uint16 _pixelNumber, uint256 _durationHours)
        public
        onlyPixelOwner(_pixelNumber)
    {
        require(_durationHours > 0);
        require(_durationHours <= 168); // Max 1 week
        require(!auctionActive[_pixelNumber]);
        
        // Vulnerable: Using block.timestamp for auction end time
        auctionEndTime[_pixelNumber] = block.timestamp + (_durationHours * 1 hours);
        auctionActive[_pixelNumber] = true;
        highestBid[_pixelNumber] = pixels[_pixelNumber].price;
        highestBidder[_pixelNumber] = pixels[_pixelNumber].owner;
    }
    
    // Place a bid on an active auction
    function placeBid(uint16 _pixelNumber)
        public
        payable
    {
        require(auctionActive[_pixelNumber]);
        require(msg.value > highestBid[_pixelNumber]);
        
        // Vulnerable: Timestamp dependence - miners can manipulate block.timestamp
        // to either extend or prematurely end auctions
        require(block.timestamp < auctionEndTime[_pixelNumber]);
        
        // Refund previous highest bidder
        if (highestBidder[_pixelNumber] != pixels[_pixelNumber].owner) {
            highestBidder[_pixelNumber].transfer(highestBid[_pixelNumber]);
        }
        
        highestBid[_pixelNumber] = msg.value;
        highestBidder[_pixelNumber] = msg.sender;
    }
    
    // Finalize auction and transfer pixel
    function finalizeAuction(uint16 _pixelNumber)
        public
    {
        require(auctionActive[_pixelNumber]);
        
        // Vulnerable: Timestamp dependence - miners can manipulate when auctions end
        require(block.timestamp >= auctionEndTime[_pixelNumber]);
        
        address originalOwner = pixels[_pixelNumber].owner;
        
        // Transfer pixel to highest bidder
        pixels[_pixelNumber].owner = highestBidder[_pixelNumber];
        pixels[_pixelNumber].price = highestBid[_pixelNumber];
        pixels[_pixelNumber].isSale = false;
        
        // Calculate and transfer fee
        uint256 fee = highestBid[_pixelNumber] / feeRate;
        originalOwner.transfer(highestBid[_pixelNumber] - fee);
        fundWallet.transfer(fee);
        
        // Reset auction state
        auctionActive[_pixelNumber] = false;
        highestBid[_pixelNumber] = 0;
        highestBidder[_pixelNumber] = address(0);
        auctionEndTime[_pixelNumber] = 0;
    }
    // === END FALLBACK INJECTION ===

    /**************************************************************************
    * public variables
    ***************************************************************************/
    uint24[10000] public colors;
    bool public isMessageEnabled;

    /**************************************************************************
    * private variables
    ***************************************************************************/
    mapping (uint16 => Pixel) private pixels;

    /**************************************************************************
    * public constants
    ***************************************************************************/
    uint16 public constant numberOfPixels = 10000;
    uint16 public constant width = 100;
    uint256 public constant feeRate = 100;

    /**************************************************************************
    * private constants
    ***************************************************************************/
    address private constant owner = 0xF1fA618D4661A8E20f665BE3BD46CAad828B5837;
    address private constant fundWallet = 0x4F6896AF8C26D1a3C464a4A03705FB78fA2aDB86;
    uint256 private constant defaultWeiPrice = 10000000000000000;   // 0.01 eth

    /**************************************************************************
    * modifiers
    ***************************************************************************/

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    modifier onlyPixelOwner(uint16 pixelNumber) {
        require(msg.sender == pixels[pixelNumber].owner);
        _;
    }

    modifier messageEnabled {
        require(isMessageEnabled == true);
        _;
    }

    /**************************************************************************
    * public methods
    ***************************************************************************/

    // constructor
    function Pixereum() public {
        isMessageEnabled = true;
    }

    /**************************************************************************
    * public methods
    ***************************************************************************/

    function getPixel(uint16 _pixelNumber)
        constant
        public
        returns(address, string, uint256, bool) 
    {
        Pixel memory pixel;
        if (pixels[_pixelNumber].owner == 0) {
            pixel = Pixel(fundWallet, "", defaultWeiPrice, true); 
        } else {
            pixel = pixels[_pixelNumber];
        }
        return (pixel.owner, pixel.message, pixel.price, pixel.isSale);
    }
    
    
    function getColors() constant public returns(uint24[10000])  {
        return colors;
    }

    // called when ether is sent to this contract
    function ()
        payable
        public 
    {
        // check if data format is valid
        // bytes[0]=x, bytes[1]=y, bytes[2-4]=color
        require(msg.data.length == 5);

        uint16 pixelNumber = getPixelNumber(msg.data[0], msg.data[1]);
        uint24 color = getColor(msg.data[2], msg.data[3], msg.data[4]);
        buyPixel(msg.sender, pixelNumber, color, "");
    }

    function buyPixel(address beneficiary, uint16 _pixelNumber, uint24 _color, string _message)
        payable
        public 
    {
        require(_pixelNumber < numberOfPixels);
        require(beneficiary != address(0));
        require(msg.value != 0);
        
        // get current pixel info
        address currentOwner;
        uint256 currentPrice;
        bool currentSaleState;
        (currentOwner, , currentPrice, currentSaleState) = getPixel(_pixelNumber);
        
        // check if a pixel is for sale
        require(currentSaleState == true);

        // check if a received Ether is higher than current price
        require(currentPrice <= msg.value);

        // calculate fee
        uint fee = msg.value / feeRate;

        // transfer received amount to current owner
        currentOwner.transfer(msg.value - fee);

        // transfer fee to fundWallet
        fundWallet.transfer(fee);

        // update pixel
        pixels[_pixelNumber] = Pixel(beneficiary, _message, currentPrice, false);
        
        // update color
        colors[_pixelNumber] = _color;
    }

    function setOwner(uint16 _pixelNumber, address _owner) 
        public
        onlyPixelOwner(_pixelNumber)
    {
        require(_owner != address(0));
        pixels[_pixelNumber].owner = _owner;
    }

    function setColor(uint16 _pixelNumber, uint24 _color) 
        public
        onlyPixelOwner(_pixelNumber)
    {
        colors[_pixelNumber] = _color;
    }

    function setMessage(uint16 _pixelNumber, string _message)
        public
        messageEnabled
        onlyPixelOwner(_pixelNumber)
    {
        pixels[_pixelNumber].message = _message;
    }

    function setPrice(uint16 _pixelNumber, uint256 _weiAmount) 
        public
        onlyPixelOwner(_pixelNumber)
    {
        pixels[_pixelNumber].price = _weiAmount;
    }

    function setSaleState(uint16 _pixelNumber, bool _isSale)
        public
        onlyPixelOwner(_pixelNumber)
    {
        pixels[_pixelNumber].isSale = _isSale;
    }

    /**************************************************************************
    * internal methods
    ***************************************************************************/

    function getPixelNumber(byte _x, byte _y)
        internal pure
        returns(uint16) 
    {
        return uint16(_x) + uint16(_y) * width;
    }

    function getColor(byte _red, byte _green, byte _blue)
        internal pure
        returns(uint24) 
    {
        return uint24(_red)*65536 + uint24(_green)*256 + uint24(_blue);
    }

    /**************************************************************************
    * methods for contract owner
    ***************************************************************************/

    // for emergency purpose
    function deleteMessage(uint16 _pixelNumber)
        onlyOwner
        public
    {
        pixels[_pixelNumber].message = "";
    }

    // for emergency purpose
    function setMessageStatus(bool _isMesssageEnabled)
        onlyOwner
        public
    {
        isMessageEnabled = _isMesssageEnabled;
    }
}
